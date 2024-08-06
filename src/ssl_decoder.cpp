#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/md5.h>

#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/safestack.h>
#include <openssl/cms.h>
#include <openssl/ocsp.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>

#include <toml/toml.h>
#include <uthash/uthash.h>
#include <uthash/utlist.h>
#include <uthash/utarray.h>
#include <uthash/utstring.h>
#include <uuid_v4/uuid_v4.h>
#include <fieldstat/fieldstat_easy.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "stellar/utils.h"
#include "stellar/session.h"
#include "stellar/stellar.h"
#include "stellar/session_mq.h"
#include "stellar/session_exdata.h"

#ifdef __cplusplus
}
#endif

#include "ssl_internal.h"
#include "ssl_decoder.h"

#define	SSL_TRUNK_MESSAGE_TOPIC	"SSL_TRUNK_MESSAGE"

UT_icd UT_ssl_hello_extension_icd={sizeof(struct ssl_decoder_ltv), NULL, NULL, NULL};

#define	SSL_TRUNK_MAGIC	0x5a5a5a5a
enum SSL_TRUNK_TYPE
{
	SSL_TRUNK_TYPE_NONE=0,
	SSL_TRUNK_TYPE_MOVE,
	SSL_TRUNK_TYPE_APPEND,
	SSL_TRUNK_TYPE_FREE,
	SSL_TRUNK_TYPE_MAX,
};

struct ssl_trunk_message
{
	uint32_t magic;
	enum SSL_TRUNK_TYPE type;
	struct ssl_record_trunk *record_trunk;
	uint8_t *pdata;
	size_t pdata_sz;
};

struct ssl_certificate_chain
{
	uint8_t *data;
	size_t data_sz;
};

struct ssl_handshake_type
{
    unsigned char content_type;
}__attribute__((packed));

struct ssl_record_header
{
    uint8_t content_type;
    uint16_t version;
    uint16_t total_len;
}__attribute__((packed));

#define SSL_RECORD_HEADER_SZ	sizeof(struct ssl_record_header)		//use the hand_shake first bytes

struct ssl_record_trunk
{
	uint8_t is_contains_header;
	struct ssl_record_header record_hdr;
	size_t data_sz;
	uint8_t *data;
};

#define	SSL_NAME_MAX	256
struct ssl_decoder_stat
{
    int32_t *metric_id;
	int32_t per_thread_enable;
	int32_t interval_second;
	char name[SSL_NAME_MAX];
	char path[SSL_NAME_MAX];
    struct fieldstat_easy *fse;
};

struct message_schema
{
    int32_t sub_id;
    int32_t topic_id;
    const char *topic_name;
    session_msg_free_cb_func *free_cb;
    on_session_msg_cb_func *on_cb;
};

struct ssl_decoder_plugin_env 
{
	int32_t max_identify_pkt;
    int32_t plugin_id;
	struct stellar *st;
	uint16_t *net_port;
	int32_t n_net_port;
    int32_t max_cache_len;
    struct message_schema ssl;
	struct message_schema ptrunk;
	struct message_schema strunk;
	struct message_schema tcp_stream;
	struct ssl_decoder_stat stat;
};

struct ssl_decoder_context
{
	int32_t identify_pkt_count;
    struct ssl_record_trunk record_trunk;
};

int32_t ssl_read_u8(uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset, uint8_t *value)
{
	if(pdata_sz<(*pdata_offset)+1)
	{
		return SSL_DECODER_FALSE;
	}

	if(value!=NULL)
	{
		*value=(uint8_t)pdata[(*pdata_offset)];
	}
	
	(*pdata_offset)++;
	return SSL_DECODER_TRUE;
}

int32_t ssl_read_be_u16(uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset, uint16_t *value)
{
	if(pdata_sz<(*pdata_offset)+2)
	{
		return SSL_DECODER_FALSE;
	}
	
	if(value!=NULL)
	{
		*value=((uint16_t)pdata[*pdata_offset] << 8) | (uint16_t)pdata[*pdata_offset+1];
	}

	(*pdata_offset)+=2;
	return SSL_DECODER_TRUE;
}

int32_t ssl_read_be_u24(uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset, uint8_t *value)
{
	if(pdata_sz<(*pdata_offset)+3)
	{
		return SSL_DECODER_FALSE;
	}

	if(value!=NULL)
	{
		ssl_read_u8(pdata, pdata_sz, pdata_offset, &value[2]);
		ssl_read_u8(pdata, pdata_sz, pdata_offset, &value[1]);
		ssl_read_u8(pdata, pdata_sz, pdata_offset, &value[0]);
	}
	else
	{
		(*pdata_offset)+=3;
	}
	
	return SSL_DECODER_TRUE;
}

int32_t ssl_read_be_u32(uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset, uint32_t *value)
{
	if(pdata_sz<(*pdata_offset)+4)
	{	
		return SSL_DECODER_FALSE;
	}
	
	if(value!=NULL)
	{
		*value=ntohl(*(uint32_t *)(pdata+(*pdata_offset)));
	}
	
	(*pdata_offset)+=4;
	return SSL_DECODER_TRUE;
}

void ssl_hello_md5sum(struct ssl_decoder_ltv *ltv, const char *str, size_t str_sz)
{
	MD5_CTX ctx;
	uint8_t md5[MD5_DIGEST_LENGTH];

    MD5_Init(&ctx);
    MD5_Update(&ctx, str, str_sz);
    MD5_Final(md5, &ctx);

	size_t offset=0;
	size_t buff_sz=MD5_DIGEST_LENGTH*2+1;
	char buff[buff_sz];

    for(int32_t n=0; n<MD5_DIGEST_LENGTH; n++)
    {
        offset+=snprintf(buff+offset, buff_sz-offset, "%.2x", md5[n]);
    }

	ltv->lv_u32=offset;
	ltv->type=SSL_DECODER_NONE;
	ltv->value=(uint8_t *)malloc(offset);
	memcpy(ltv->value, buff, offset);
}

// https://tools.ietf.org/html/draft-davidben-tls-grease-00
static int32_t ssl_is_grease_value(unsigned short val)
{
	if((val & 0x0f)!=0x0a)
	{
		return SSL_DECODER_FALSE;
	}

	if((val & 0xff) != ((val >> 8) & 0xff))
	{
		return SSL_DECODER_FALSE;
	}

	return SSL_DECODER_TRUE;
}

void ssl_trunk_free(struct ssl_record_trunk *record_trunk)
{
    if(record_trunk!=NULL)
    {
        if(record_trunk->data!=NULL)
        {
            FREE(record_trunk->data);
        }

		record_trunk->data=NULL;
        record_trunk->data_sz=0;
		record_trunk->is_contains_header=SSL_DECODER_TRUE;
		record_trunk->record_hdr={0};
    }
}

void ssl_trunk_cache(struct ssl_record_trunk *record_trunk, enum SSL_TRUNK_TYPE type, uint8_t *fragment, size_t fragment_sz)
{
	if(record_trunk==NULL || fragment==NULL || fragment_sz==0)
	{
		return ;
	}

	switch(type)
	{
		case	SSL_TRUNK_TYPE_MOVE:
			{
				uint8_t *tmp=(uint8_t *)malloc(fragment_sz);
				memcpy(tmp, fragment, fragment_sz);
				if(record_trunk->data!=NULL)
				{
					FREE(record_trunk->data);
				}
				record_trunk->data=tmp;
				record_trunk->data_sz=fragment_sz;
			}
			break;
		case	SSL_TRUNK_TYPE_APPEND:
			record_trunk->data=(record_trunk->data==NULL) ? (uint8_t *)malloc(fragment_sz) : (uint8_t *)realloc(record_trunk->data, record_trunk->data_sz+fragment_sz);
			memcpy(record_trunk->data+record_trunk->data_sz, fragment, fragment_sz);
			record_trunk->data_sz+=fragment_sz;
			break;
		default:
			break;
	}
}

int32_t is_trunk_cache(struct ssl_record_trunk *record_trunk)
{
    return ((record_trunk->data_sz>0) ? SSL_DECODER_TRUE : SSL_DECODER_FALSE);
}

int32_t ssl_record_header_get(struct ssl_record_header *record_hdr, uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset)
{
	if(pdata_sz<(*pdata_offset)+SSL_RECORD_HEADER_SZ)
	{
		return SSL_DECODER_FALSE;
	}

	ssl_read_u8(pdata, pdata_sz, pdata_offset, &(record_hdr->content_type));
	ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(record_hdr->version));
	ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(record_hdr->total_len));

	return SSL_DECODER_TRUE;
}

void ssl_recod_buff_get0(struct ssl_record_trunk *record_trunk, uint8_t **record_buff, size_t *record_buff_sz)
{
    if(!is_trunk_cache(record_trunk) && (*record_buff_sz)>SSL_RECORD_HEADER_SZ)
    {
        return ;
    }

	if(record_trunk->is_contains_header==SSL_DECODER_TRUE)
	{
		ssl_trunk_cache(record_trunk, SSL_TRUNK_TYPE_APPEND, (*record_buff), (*record_buff_sz));
	}
	else
	{
		size_t offset=0;
		struct ssl_record_header record_hdr={0};
		ssl_record_header_get(&record_hdr, *record_buff, *record_buff_sz, &offset);
		if(record_hdr.content_type!=record_trunk->record_hdr.content_type)
		{
			ssl_trunk_free(record_trunk);
			return ;
		}

		if((*record_buff_sz)<SSL_RECORD_HEADER_SZ)
		{
			return ;
		}
		
		ssl_trunk_cache(record_trunk, SSL_TRUNK_TYPE_APPEND, (*record_buff)+SSL_RECORD_HEADER_SZ, (*record_buff_sz)-SSL_RECORD_HEADER_SZ);
	}
    

    (*record_buff)=record_trunk->data;
    (*record_buff_sz)=record_trunk->data_sz;
}

void ssl_trunk_message_segment_data_cb(struct session *ss, int32_t topic_id, const void *msg, void *per_session_ctx, void *penv)
{
	struct ssl_trunk_message *trunk_msg=(struct ssl_trunk_message *)msg;
	if(trunk_msg==NULL || trunk_msg->magic!=SSL_TRUNK_MAGIC)
	{
		return ;
	}

	switch(trunk_msg->type)
	{
		case	SSL_TRUNK_TYPE_MOVE:
			ssl_trunk_cache(trunk_msg->record_trunk, SSL_TRUNK_TYPE_MOVE, trunk_msg->pdata, trunk_msg->pdata_sz);
			break;
		case	SSL_TRUNK_TYPE_APPEND:
			ssl_trunk_cache(trunk_msg->record_trunk, SSL_TRUNK_TYPE_APPEND, trunk_msg->pdata, trunk_msg->pdata_sz);
			break;
		case	SSL_TRUNK_TYPE_FREE:
			ssl_trunk_free(trunk_msg->record_trunk);
			break;
		default:
			break;
	}
}

void ssl_trunk_message_publish(struct ssl_decoder_plugin_env *plugin_env, struct session *ss, struct ssl_record_trunk *record_trunk, uint8_t *pdata, size_t pdata_sz)
{
	struct ssl_trunk_message *message=(struct ssl_trunk_message *)malloc(sizeof(struct ssl_trunk_message));
	message->magic=SSL_TRUNK_MAGIC;
	message->record_trunk=record_trunk;
	message->pdata=pdata;
	message->pdata_sz=pdata_sz;
	if(pdata_sz==0)
	{
		message->type=SSL_TRUNK_TYPE_FREE;
	}
	else
	{
		message->type=((is_trunk_cache(record_trunk)) ? SSL_TRUNK_TYPE_MOVE : SSL_TRUNK_TYPE_APPEND);
	}

	if(((long long)pdata_sz) <0)
	{
		abort();
	}

	session_mq_publish_message(ss, plugin_env->ptrunk.topic_id, (void *)message);
}

void ssl_trunk_message_free(struct session *sess, void *msg, void *msg_free_arg)
{
	struct ssl_trunk_message *trunk_msg=(struct ssl_trunk_message *)msg;
	if(trunk_msg==NULL)
	{
		return ;
	}

	FREE(trunk_msg);
}

int32_t ssl_decoder_ltv_get(struct ssl_decoder_ltv *ltv, uint16_t type, uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset)
{
	if(ltv==NULL || pdata==NULL || pdata_sz<(*pdata_offset))
	{
		return SSL_DECODER_FALSE;
	}

	int32_t ret=SSL_DECODER_FALSE;
	switch(type)
	{
		case	SSL_DECODER_L1V:
			ret=ssl_read_u8(pdata, pdata_sz, pdata_offset, &(ltv->lv_u8));
			break;
		case	SSL_DECODER_L2V:
			ret=ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(ltv->lv_u16));
			break;
		case	SSL_DECODER_L2TV:
			ret=ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(ltv->vtype));
			if(ret==SSL_DECODER_FALSE)
			{
				return SSL_DECODER_FALSE;
			}
			ret=ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(ltv->lv_u16));
			break;
		default:
			break;
	}

	if(ret==SSL_DECODER_TRUE)
	{
		ltv->type=type;
		ltv->value=pdata+(*pdata_offset);
		(*pdata_offset)+=ltv->lv_u32;
	}

	return ret;
}

uint32_t ssl_handshake_certificate_count_get(uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset, struct ssl_certificate_chain *cert_chain, uint32_t cert_chain_num)
{
	if(NULL==pdata || 0==pdata_sz)
	{
		return 0;
	}

	uint32_t count=0;
	size_t offset=(*pdata_offset);

	while(pdata_sz > offset)
	{
		if(count>=cert_chain_num)
		{
			break;
		}
		
		int32_t one_cert_sz=0;
		int32_t ret=ssl_read_be_u24(pdata, pdata_sz, &offset, (uint8_t *)&(one_cert_sz));
		if(ret==SSL_DECODER_FALSE || one_cert_sz<=0 || (one_cert_sz+offset) > pdata_sz)
		{
			break;
		}

		cert_chain[count].data=pdata+offset;
		cert_chain[count].data_sz=one_cert_sz;
		offset+=one_cert_sz;
		count++;
	}
	
	return count;
}

enum ssl_certificate_type ssl_handshake_certificate_type_get(uint32_t count, uint32_t offset)
{
	if(offset>=count)
	{
		return SSL_CERTIFICATE_TYPE_UNKNOWN;
	}

	switch(offset)
	{
		case 0:
			return SSL_CERTIFICATE_TYPE_INDIVIDUAL;
		case 1:
			return ((count==2) ? SSL_CERTIFICATE_TYPE_ROOT : SSL_CERTIFICATE_TYPE_MIDDLE);
		case 2:
			return ((count==3) ? SSL_CERTIFICATE_TYPE_ROOT : SSL_CERTIFICATE_TYPE_CHAIN);		
		default:
			break;
	}

	return (offset==count-1) ? SSL_CERTIFICATE_TYPE_ROOT : SSL_CERTIFICATE_TYPE_CHAIN;
}

int32_t ssl_x509_certificate_detail_decode(struct ssl_certificate *certificate, uint8_t *pdata, int32_t pdata_sz)
{
	X509_NAME *issuer=NULL;
    X509_NAME *subject=NULL;

    ASN1_STRING *serial=NULL;
	ASN1_STRING *san_name=NULL;
    
	GENERAL_NAME *generalName=NULL;
    GENERAL_NAMES *subjectAltNames=NULL;
    
    ASN1_TIME *start=NULL;
    ASN1_TIME *end=NULL;
	
	EVP_PKEY *pkey=NULL;
	const ASN1_OBJECT *salg;
    const X509_ALGOR *tsig_alg;
	
	X509 *x509_handle=d2i_X509(NULL, (unsigned char const **)&pdata, pdata_sz);
	if(x509_handle==NULL)
	{
		return SSL_DECODER_FALSE;
	}
	
    /*version*/
    certificate->version=X509_get_version(x509_handle);
    if(certificate->version>SSL_CERTIFICATE_VERSION_MAX) 
    {
        X509_free(x509_handle);
		return SSL_DECODER_FALSE;
    }

    /*serial num*/
    serial=X509_get_serialNumber(x509_handle);
    if(NULL != serial)
    {
        certificate->serial.len=MIN(ASN1_STRING_length(serial), (int)(sizeof(certificate->serial.value)-1));
        memcpy(certificate->serial.value, ASN1_STRING_get0_data(serial), certificate->serial.len);
    }

    /*SSL AgID*/
    tsig_alg=X509_get0_tbs_sigalg(x509_handle);
    X509_ALGOR_get0(&salg, NULL, NULL, tsig_alg);
    OBJ_obj2txt((char*)certificate->signature_algorithm.value, sizeof(certificate->signature_algorithm.value), salg, 1);
    certificate->signature_algorithm.len=strlen((const char *)certificate->signature_algorithm.value);

    /*SSL Issuer*/
    issuer=X509_get_issuer_name(x509_handle);
    if(NULL!=issuer)
    {
        X509_NAME_get_text_by_NID(issuer, NID_commonName, certificate->issuer.common, sizeof(certificate->issuer.common));
        X509_NAME_get_text_by_NID(issuer, NID_organizationName, certificate->issuer.organization, sizeof(certificate->issuer.organization));
        X509_NAME_get_text_by_NID(issuer, NID_organizationalUnitName, certificate->issuer.organizational_unit, sizeof(certificate->issuer.organizational_unit));
        X509_NAME_get_text_by_NID(issuer, NID_localityName, certificate->issuer.locality, sizeof(certificate->issuer.locality));
        X509_NAME_get_text_by_NID(issuer, NID_streetAddress, certificate->issuer.street_address, sizeof(certificate->issuer.street_address));
        X509_NAME_get_text_by_NID(issuer, NID_stateOrProvinceName, certificate->issuer.state_or_Province, sizeof(certificate->issuer.state_or_Province));			
        X509_NAME_get_text_by_NID(issuer, NID_countryName,  certificate->issuer.country, sizeof(certificate->issuer.country));

        snprintf(certificate->issuer.rdn_sequence_list,
                    sizeof(certificate->issuer.rdn_sequence_list),
                    "%s;%s;%s;%s;%s;%s;%s",
                    certificate->issuer.common,
                    certificate->issuer.organization,
                    certificate->issuer.organizational_unit,
                    certificate->issuer.locality,
                    certificate->issuer.street_address,
                    certificate->issuer.state_or_Province,
                    certificate->issuer.country);
    }

    /*SSL Subject*/
    subject=X509_get_subject_name(x509_handle);
    if(NULL!=subject)
    {
        X509_NAME_get_text_by_NID(subject, NID_commonName, certificate->subject.common, sizeof(certificate->subject.common));
        X509_NAME_get_text_by_NID(subject, NID_organizationName, certificate->subject.organization, sizeof(certificate->subject.organization));
        X509_NAME_get_text_by_NID(subject, NID_countryName, certificate->subject.country, sizeof(certificate->subject.country));
        X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, certificate->subject.organizational_unit, sizeof(certificate->subject.organizational_unit));
        X509_NAME_get_text_by_NID(subject, NID_localityName, certificate->subject.locality, sizeof(certificate->subject.locality));
        X509_NAME_get_text_by_NID(subject, NID_streetAddress, certificate->subject.street_address, sizeof(certificate->subject.street_address));
        X509_NAME_get_text_by_NID(subject, NID_stateOrProvinceName, certificate->subject.state_or_Province, sizeof(certificate->subject.state_or_Province));			
        
        snprintf(certificate->subject.rdn_sequence_list,
                    sizeof(certificate->subject.rdn_sequence_list),
                    "%s;%s;%s;%s;%s;%s;%s",
                    certificate->subject.common,
                    certificate->subject.organization,
                    certificate->subject.organizational_unit,
                    certificate->subject.locality,
                    certificate->subject.street_address,
                    certificate->subject.state_or_Province,
                    certificate->subject.country);
    }

    /*SSL Subject keyInfo*/
    pkey=X509_get_pubkey(x509_handle);
    if(pkey!=NULL)
    {
    	//https://www.openssl.org/docs/man3.0/man3/i2d_PublicKey.html
        certificate->subject_key.len=i2d_PublicKey(pkey, NULL);
		if(certificate->subject_key.len>0)
		{
	        certificate->subject_key.value=(char *)malloc(certificate->subject_key.len);		
	        int32_t ret=i2d_PublicKey(pkey, (unsigned char **)&(certificate->subject_key.value)); //!!! point32_t will be changed
	        if(ret>0)
	        {
	        	 certificate->subject_key.value=certificate->subject_key.value-certificate->subject_key.len;
	        }
			else
			{
				free(certificate->subject_key.value);
				certificate->subject_key.value=NULL;
				certificate->subject_key.len=0;
			}
		}
        EVP_PKEY_free(pkey);
    }		
            
    /*validity*/
    start=X509_get_notBefore(x509_handle);
    end=X509_get_notAfter(x509_handle);
    sprintf(certificate->validity.before, "%s", start->data);
    sprintf(certificate->validity.after, "%s", end->data);				

    /*subject bak*/	
    subjectAltNames=(GENERAL_NAMES*)X509_get_ext_d2i(x509_handle, NID_subject_alt_name, NULL, NULL);  
    if(!subjectAltNames)
    {
        X509_free(x509_handle);
		return SSL_DECODER_TRUE;
    }

    int32_t san_count=sk_GENERAL_NAME_num(subjectAltNames);
    if(san_count>0)
    {
        certificate->subject_alter.num=0;
        certificate->subject_alter.name=(char (*)[MAX_ALTER_NAME_LEN])malloc(san_count * sizeof(char[MAX_ALTER_NAME_LEN]));
        
        for (int32_t i=0; i<san_count; i++)
        {       
            generalName=sk_GENERAL_NAME_value(subjectAltNames, i);
            if(!generalName)
            {
                break;
            }

            if(GEN_DNS == generalName->type)
            {
                san_name=(ASN1_STRING*)GENERAL_NAME_get0_value(generalName, NULL);
                if(ASN1_STRING_length(san_name)>0)
                {
                    char *san=(char*)ASN1_STRING_get0_data(san_name);
                    int32_t length=MIN(strlen(san), sizeof(certificate->subject_alter.name[certificate->subject_alter.num])-1);
                    memcpy(certificate->subject_alter.name[certificate->subject_alter.num], san, length);
					certificate->subject_alter.name[certificate->subject_alter.num][length]='\0';
                    certificate->subject_alter.num++;
                }	
            }			
        }
    }

    if(subjectAltNames)
    {
        GENERAL_NAMES_free(subjectAltNames);
    }

    //https://www.openssl.org/docs/man1.1.1/man3/X509_ALGOR_get0.html
    X509_ALGOR_get0(&salg, NULL, NULL, X509_get0_tbs_sigalg(x509_handle));
    OBJ_obj2txt(certificate->algorithm_identifier.value, sizeof(certificate->algorithm_identifier.value), salg, 1);
    certificate->algorithm_identifier.len=strlen((const char *)certificate->algorithm_identifier.value);

	return SSL_DECODER_TRUE;
}

int32_t ssl_decoder_random_bytes_get(struct ssl_decoder_ltv *ltv, uint16_t type, uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset)
{
	if(pdata_sz<(*pdata_offset)+SSL_RANDOM_SIZE)
	{
		return SSL_DECODER_FALSE;
	}

	ltv->type=type;
	ltv->lv_u16=SSL_RANDOM_SIZE;
	ltv->value=pdata+(*pdata_offset);
	(*pdata_offset)+=SSL_RANDOM_SIZE;

	return SSL_DECODER_TRUE;
}

int32_t ssl_server_name_decode(struct ssl_decoder_ltv *sni, uint8_t *pdata, uint16_t pdata_sz)
{
	if(sni==NULL || pdata==NULL || pdata_sz<2)
	{
		return SSL_DECODER_FALSE;
	}

	size_t offset=0;
	uint16_t name_list_sz=0;
	ssl_read_be_u16(pdata, pdata_sz, &offset, &(name_list_sz));

	while(name_list_sz-offset>3)	// 3=sizeof(vtype)+sizeof(vlen)
	{
		uint8_t vtype=0;
		uint16_t vlen=0;
		ssl_read_u8(pdata, pdata_sz, &offset, &(vtype));
		ssl_read_be_u16(pdata, pdata_sz, &offset, &(vlen));
		if(vtype!=SERVER_NAME_HOST_TYPE)
		{
			continue;
		}

		if(vlen==0 || vlen>(pdata_sz-offset))
		{
			return SSL_DECODER_FALSE;
		}

		sni->type=SSL_DECODER_L1V;
		sni->lv_u16=vlen;
		sni->value=pdata+offset;
		offset+=vlen;
		break;
	}

	return SSL_DECODER_TRUE;
}

struct ssl_server_hello *ssl_handshake_server_hello_decode(uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset)
{
	int32_t ret=SSL_DECODER_FALSE;
	struct ssl_server_hello *shello=(struct ssl_server_hello *)CALLOC(struct ssl_server_hello, 1);
	ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(shello->version));
	ssl_read_be_u32(pdata, pdata_sz, pdata_offset, &(shello->random_gmt_time));

	for(int32_t i=1; i<SSL_HELLO_LTV_MAX; i++)
	{
		struct ssl_decoder_ltv *ltv=&(shello->ltv[i]);
		switch(i)
		{
			case	SSL_HELLO_LTV_RANDOM_BYTES:
				ret=ssl_decoder_random_bytes_get(ltv, SSL_DECODER_NONE, pdata, pdata_sz, pdata_offset);
				break;
			case	SSL_HELLO_LTV_SESSION:
				ret=ssl_decoder_ltv_get(ltv, SSL_DECODER_L1V, pdata, pdata_sz, pdata_offset);
				break;
			case	SSL_HELLO_LTV_CIPERSUITES:
				shello->ltv[i].lv_u16=2;
				shello->ltv[i].value=pdata+(*pdata_offset);
				(*pdata_offset)+=2;
				break;
			case	SSL_HELLO_LTV_COMPRESS_METHOD:
				shello->ltv[i].lv_u16=1;
				shello->ltv[i].value=pdata+(*pdata_offset);
				(*pdata_offset)+=1;
				break;
			default:
				break;
		}

		if(ret==SSL_DECODER_FALSE)
		{
			FREE(shello);
			return NULL;
		}
	}

	/*get extension*/
	uint16_t extension_len=0;
	ret=ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &extension_len);
	if(ret==SSL_DECODER_FALSE || (extension_len+(*pdata_offset)>pdata_sz))
	{
		FREE(shello);
		return NULL;
	}

	if(extension_len==0)
	{
		return shello;
	}

	size_t offset=(*pdata_offset);
	utarray_new(shello->extensions, &UT_ssl_hello_extension_icd);

	for(size_t i=0; pdata_sz>offset && (offset-(*pdata_offset))<extension_len; i++) // min len of ext is 4 byte
	{
		struct ssl_decoder_ltv ltv={0};
		ret=ssl_decoder_ltv_get(&ltv, SSL_DECODER_L2TV, pdata, pdata_sz, &offset);
		if(ret==SSL_DECODER_FALSE)
		{
			break;
		}

		utarray_push_back(shello->extensions, &ltv);
	}

	(*pdata_offset)=offset;
	
	return shello;
}

struct ssl_client_hello *ssl_handshake_client_hello_decode(uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset)
{
	int32_t ret=SSL_DECODER_FALSE;
	struct ssl_client_hello *chello=(struct ssl_client_hello *)CALLOC(struct ssl_client_hello, 1);
	ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(chello->version));
	ssl_read_be_u32(pdata, pdata_sz, pdata_offset, &(chello->random_gmt_time));

	for(int32_t i=1; i<SSL_HELLO_LTV_MAX; i++)
	{
		struct ssl_decoder_ltv *ltv=&(chello->ltv[i]);
		switch(i)
		{
			case	SSL_HELLO_LTV_RANDOM_BYTES:
				ret=ssl_decoder_random_bytes_get(ltv, SSL_DECODER_NONE, pdata, pdata_sz, pdata_offset);
				break;
			case	SSL_HELLO_LTV_SESSION:
				ret=ssl_decoder_ltv_get(ltv, SSL_DECODER_L1V, pdata, pdata_sz, pdata_offset);
				break;
			case	SSL_HELLO_LTV_CIPERSUITES:
				ret=ssl_decoder_ltv_get(ltv, SSL_DECODER_L2V, pdata, pdata_sz, pdata_offset);
				break;
			case	SSL_HELLO_LTV_COMPRESS_METHOD:
				ret=ssl_decoder_ltv_get(ltv, SSL_DECODER_L1V, pdata, pdata_sz, pdata_offset);
				break;
			default:
				break;
		}

		if(ret==SSL_DECODER_FALSE)
		{
			FREE(chello);
			return NULL;
		}
	}

	/*get extension*/
	uint16_t extension_len=0;
	ret=ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &extension_len);
	if(ret==SSL_DECODER_FALSE || (extension_len+(*pdata_offset)>pdata_sz))
	{
		FREE(chello);
		return NULL;
	}

	if(extension_len==0)
	{
		return chello;
	}

	utarray_new(chello->extensions, &UT_ssl_hello_extension_icd);

	for(size_t i=0; pdata_sz>(*pdata_offset); i++) // min len of ext is 4 byte
	{
		struct ssl_decoder_ltv ltv={0};
		ret=ssl_decoder_ltv_get(&ltv, SSL_DECODER_L2TV, pdata, pdata_sz, pdata_offset);
		if(ret==SSL_DECODER_FALSE)
		{
			break;
		}

		utarray_push_back(chello->extensions, &ltv);

		switch(ltv.vtype)
		{
			case	SERVER_NAME_EXT_TYPE:
				{
					struct ssl_decoder_ltv sni={0};
					ret=ssl_server_name_decode(&sni, ltv.value, ltv.lv_u16);
					if(ret==SSL_DECODER_TRUE)
					{
						chello->sni=(struct ssl_decoder_ltv *)malloc(sizeof(struct ssl_decoder_ltv));
						memcpy(chello->sni, &sni, sizeof(struct ssl_decoder_ltv));
					}
				}
				break;
			case	ENCRPTED_SERVER_NAME_EXT_TYPE:
				chello->esni=(struct ssl_decoder_ltv *)malloc(sizeof(struct ssl_decoder_ltv));
				memcpy(chello->esni, &ltv, sizeof(struct ssl_decoder_ltv));
				break;
			case	ENCRPTED_CLIENT_HELLO_EXT_TYPE:
				chello->ech=(struct ssl_decoder_ltv *)malloc(sizeof(struct ssl_decoder_ltv));
				memcpy(chello->ech, &ltv, sizeof(struct ssl_decoder_ltv));
				break;
			default:
				break;
		}
	}

	return chello;
}

int32_t ssl_server_hello_ja3s_generate(struct ssl_server_hello *shello)
{
	if(shello==NULL)
	{
		return SSL_DECODER_FALSE;
	}

	UT_string *ja3s_string;
	utstring_new(ja3s_string);
	utstring_printf(ja3s_string, "%u,", shello->version);

	int32_t flag=SSL_DECODER_FALSE;
	size_t offset=0;
	struct ssl_decoder_ltv *cipher_suites=&(shello->ltv[SSL_HELLO_LTV_CIPERSUITES]);
	for(; offset<cipher_suites->lv_u16; )
	{
		uint16_t cipher_suite=0;
		ssl_read_be_u16(cipher_suites->value, cipher_suites->lv_u16, &offset, &cipher_suite);
		if(ssl_is_grease_value(cipher_suite))
		{
			continue;
		}
		
		utstring_printf(ja3s_string, "%s%u", ((flag==SSL_DECODER_FALSE) ? "" : "-"), cipher_suite);
		flag=SSL_DECODER_TRUE;
	}
	
	utstring_printf(ja3s_string, "%s", ",");

	flag=SSL_DECODER_FALSE;
	for(uint32_t i=0; i<utarray_len(shello->extensions); i++)
	{
		struct ssl_decoder_ltv *ext=(struct ssl_decoder_ltv *)utarray_eltptr(shello->extensions, i);
		if(ext==NULL || ssl_is_grease_value(ext->vtype))
		{
			continue;
		}

		utstring_printf(ja3s_string, "%s%u", ((flag==SSL_DECODER_FALSE) ? "" : "-"), ext->vtype);
		flag=SSL_DECODER_TRUE;
	}

	ssl_hello_md5sum(&(shello->ja3s), utstring_body(ja3s_string), utstring_len(ja3s_string));
	utstring_free(ja3s_string);

	return SSL_DECODER_TRUE;
}

int32_t ssl_client_hello_ja3_generate(struct ssl_client_hello *chello)
{
	if(chello==NULL)
	{
		return SSL_DECODER_FALSE;
	}

	UT_string *ja3_string;
	utstring_new(ja3_string);
	utstring_printf(ja3_string, "%u,", chello->version);

	int32_t flag=SSL_DECODER_FALSE;
	size_t offset=0;
	struct ssl_decoder_ltv *cipher_suites=&(chello->ltv[SSL_HELLO_LTV_CIPERSUITES]);
	for(; offset<cipher_suites->lv_u16; )
	{
		uint16_t cipher_suite=0;
		ssl_read_be_u16(cipher_suites->value, cipher_suites->lv_u16, &offset, &cipher_suite);
		if(ssl_is_grease_value(cipher_suite))
		{
			continue;
		}
		
		utstring_printf(ja3_string, "%s%u", ((flag==SSL_DECODER_FALSE) ? "" : "-"), cipher_suite);
		flag=SSL_DECODER_TRUE;
	}
	
	utstring_printf(ja3_string, "%s", ",");

	flag=SSL_DECODER_FALSE;
	struct ssl_decoder_ltv *ec=NULL;
	struct ssl_decoder_ltv *ec_point_format=NULL;

	for(uint32_t i=0; i<utarray_len(chello->extensions); i++)
	{
		struct ssl_decoder_ltv *ext=(struct ssl_decoder_ltv *)utarray_eltptr(chello->extensions, i);
		if(ext==NULL || ssl_is_grease_value(ext->vtype))
		{
			continue;
		}

		utstring_printf(ja3_string, "%s%u", ((flag==SSL_DECODER_FALSE) ? "" : "-"), ext->vtype);
		flag=SSL_DECODER_TRUE;
		
		switch(ext->vtype)
		{
			case	EC_POINT_FORMATS_EXT_TYPE:
				ec_point_format=ext;
				break;
			case	SUPPORTED_GROUPS_EXT_TYPE:
				ec=ext;
				break;
			default:
				break;
		}
	}

	utstring_printf(ja3_string, "%s", ",");
	
	if(ec!=NULL && ec->value!=NULL && ec->lv_u16>0)
	{
		offset=0;
		uint16_t length=0;
		ssl_read_be_u16(ec->value, ec->lv_u16, &offset, &length);

		flag=SSL_DECODER_FALSE;
		for(;  ec->lv_u16 > offset; )
		{
			uint16_t group=0;
			ssl_read_be_u16(ec->value, ec->lv_u16, &offset, &group);
			if(ssl_is_grease_value(group))
			{
				continue;
			}

			utstring_printf(ja3_string, "%s%u", ((flag==SSL_DECODER_FALSE) ? "" : "-"), group);
			flag=SSL_DECODER_TRUE;
		}
	}

	utstring_printf(ja3_string, "%s", ",");

	if(ec_point_format!=NULL && ec_point_format->value!=NULL && ec_point_format->lv_u16>0)
	{
		offset=0;
		uint8_t length=0;
		ssl_read_u8(ec_point_format->value, ec_point_format->lv_u16, &offset, &length);

		for(uint8_t j=0; j<length && (length < ec_point_format->lv_u16); j++)
		{
			utstring_printf(ja3_string, "%s%u", ((j==0) ? "" : "-"), ec_point_format->value[offset++]);
		}
	}

	ssl_hello_md5sum(&(chello->ja3), utstring_body(ja3_string), utstring_len(ja3_string));
	utstring_free(ja3_string);

	return SSL_DECODER_TRUE;
}

void ssl_message_publish(struct ssl_decoder_plugin_env *plugin_env, struct session *ss, enum ssl_message_type type, void *data, size_t data_sz)
{
	struct ssl_message *message=(struct ssl_message *)malloc(sizeof(struct ssl_message));
	message->magic=SSL_MESSAGE_MAGIC;
	message->type=type;
	message->ss=ss;
	message->plugin_env=plugin_env;
	message->data=data;
	message->data_sz=data_sz;

	session_mq_publish_message(ss, plugin_env->ssl.topic_id, (void *)message);
}

void ssl_message_free(struct session *sess, void *msg, void *msg_free_arg)
{
	struct ssl_message *message=(struct ssl_message *)msg;
	if(message==NULL || message->magic!=SSL_MESSAGE_MAGIC)
	{
		return ;
	}

	if(message->data!=NULL)
	{
		switch(message->type)
		{
			case	SSL_MESSAGE_CLIENT_HELLO:
				{
					struct ssl_client_hello *chello=(struct ssl_client_hello *)message->data;
					if(chello->extensions!=NULL)
					{
						utarray_free(chello->extensions);
					}

					FREE(message->data);
				}
				break;
			case	SSL_MESSAGE_SERVER_HELLO:
				{
					struct ssl_server_hello *shello=(struct ssl_server_hello *)message->data;
					if(shello->extensions!=NULL)
					{
						utarray_free(shello->extensions);
					}

					FREE(message->data);
				}
				break;
			case	SSL_MESSAGE_CERTIFICATE:
				{
					struct ssl_certificate *certificate=(struct ssl_certificate *)message->data;
					if(certificate->subject_alter.name!=NULL)
					{
						FREE(certificate->subject_alter.name);
					}

					if(certificate->subject_key.value!=NULL)
					{
						FREE(certificate->subject_key.value);
					}

					FREE(message->data);
				}
				break;
			default:
				break;
		}
	}

	FREE(message);
}

int32_t ssl_handshake_decode(struct ssl_decoder_plugin_env *plugin_env, struct session *ss, uint8_t *pdata, size_t pdata_sz, size_t *pdata_offset, size_t total_sz)
{
	if(pdata==NULL || ((*pdata_offset)+1>pdata_sz))
	{
		return SSL_DECODER_FALSE;
	}

	size_t hd_offset=0;
	while(total_sz>hd_offset && pdata_sz>(*pdata_offset))
	{
		struct ssl_handshake_type *handshake_type=(struct ssl_handshake_type *)(pdata+(*pdata_offset));
		if(handshake_type->content_type==SSL_HANDSHAKE_ENCRYPTED_MESSAGE)
		{
			hd_offset=total_sz;
			(*pdata_offset)+=total_sz;
			return SSL_DECODER_TRUE;
		}

		(*pdata_offset)+=sizeof(struct ssl_handshake_type);

		int32_t total_len=0;
		int32_t ret=ssl_read_be_u24(pdata, pdata_sz, pdata_offset, (uint8_t *)&total_len);
		if(ret==SSL_DECODER_FALSE)
		{
			return SSL_DECODER_CONTINUE;
		}

		if(total_len<0)
		{
			return SSL_DECODER_FALSE;
		}

		if(total_len+(*pdata_offset)>pdata_sz)
		{
			return SSL_DECODER_CONTINUE;
		}

		size_t offset=(*pdata_offset);
		(*pdata_offset)+=total_len;
		hd_offset+=total_len+4;

		switch(handshake_type->content_type)
		{
			case	SSL_HANDSHAKE_CLIENT_HELLO:
				{
					struct ssl_client_hello *chello=ssl_handshake_client_hello_decode(pdata, pdata_sz, &offset);
					ssl_client_hello_ja3_generate(chello);
					ssl_message_publish(plugin_env, ss, SSL_MESSAGE_CLIENT_HELLO, (void *)chello, sizeof(struct ssl_client_hello));
				}
				break;
			case	SSL_HANDSHAKE_SERVER_HELLO:
				{
					struct ssl_server_hello *shello=ssl_handshake_server_hello_decode(pdata, pdata_sz, &offset);
					ssl_server_hello_ja3s_generate(shello);
					ssl_message_publish(plugin_env, ss, SSL_MESSAGE_SERVER_HELLO, (void *)shello, sizeof(struct ssl_server_hello));
				}
				break;
			case	SSL_HANDSHAKE_CERTIFICATE:
				{
					int32_t cert_total_len=0;
					ret=ssl_read_be_u24(pdata, pdata_sz, &offset, (uint8_t *)&cert_total_len);
					if(ret==SSL_DECODER_FALSE || cert_total_len<0 || cert_total_len+offset>pdata_sz || (cert_total_len+3)!=total_len)
					{
						break;
					}

					struct ssl_certificate_chain cert_unit[SSL_CERTIFICATE_NUM_MAX];
					uint32_t cert_count=ssl_handshake_certificate_count_get(pdata, pdata_sz, &offset, cert_unit, SSL_CERTIFICATE_NUM_MAX);

					for(uint32_t i=0, cert_offset=0; i<cert_count; i++, cert_offset++)
					{
						struct ssl_certificate *certificate=(struct ssl_certificate *)CALLOC(struct ssl_certificate, 1);

						certificate->type=ssl_handshake_certificate_type_get(cert_count, cert_offset);
						int32_t state=ssl_x509_certificate_detail_decode(certificate, cert_unit[i].data, cert_unit[i].data_sz);
						if(state==SSL_DECODER_FALSE)
						{
							FREE(certificate);
							break;
						}

						ssl_message_publish(plugin_env, ss, SSL_MESSAGE_CERTIFICATE, (void *)certificate, sizeof(struct ssl_certificate));
					}
				}
				break;
			case	SSL_HANDSHAKE_SERVER_KEY_EXCHANGE:
			default:
				break;
		}
	}

	return SSL_DECODER_TRUE;
}

void ssl_tcp_stream_session_segment_data_cb(struct session *ss, int32_t topic_id, const void *msg, void *per_session_ctx, void *penv)
{
	size_t pdata_offset=0;
    size_t pdata_sz=0;
    uint8_t *pdata=NULL;
    pdata=(uint8_t *)session_get0_current_payload(ss, &pdata_sz);
    if(pdata_sz==0 || pdata==NULL)
    {
        return ;
    }

    // fragment: 1: less than SSL_RECORD_HEADER_SZ; 2: less than the length of the message; 3: multiple record messages
	struct ssl_decoder_plugin_env *plugin_env=(struct ssl_decoder_plugin_env *)penv;
	struct ssl_decoder_context *per_ss_ctx=(struct ssl_decoder_context *)(per_session_ctx);
    ssl_recod_buff_get0(&(per_ss_ctx->record_trunk), &pdata, &pdata_sz);
    if(pdata_sz<=SSL_RECORD_HEADER_SZ)
    {
        return ;
    }

	while(pdata_sz>pdata_offset)
	{
		struct ssl_record_header record_hdr={0};
		if(per_ss_ctx->record_trunk.is_contains_header==SSL_DECODER_TRUE)
		{
			ssl_record_header_get(&record_hdr, pdata, pdata_sz, &pdata_offset);
		}
		else
		{
			record_hdr=per_ss_ctx->record_trunk.record_hdr;
			record_hdr.total_len=pdata_sz;
		}

		int32_t ret=SSL_DECODER_TRUE;
		size_t offset=pdata_offset;
		switch(record_hdr.content_type)
		{
			case	SSL_CONTENT_TYPE_HANDSHAKE:
				if(pdata_sz-pdata_offset<record_hdr.total_len)
				{
					pdata_offset-=5;
					ret=SSL_DECODER_FALSE;
					per_ss_ctx->record_trunk.record_hdr=record_hdr;
					per_ss_ctx->record_trunk.is_contains_header=SSL_DECODER_TRUE;
					break;
				}
				else
				{
					ret=ssl_handshake_decode(plugin_env, ss, pdata, pdata_sz, &offset, record_hdr.total_len);
					pdata_offset=((ret==SSL_DECODER_FALSE) ? pdata_sz : pdata_offset);
				}
				break;
			case	SSL_CONTENT_TYPE_APPLICATION_DATA:
				ssl_message_publish(plugin_env, ss, SSL_MESSAGE_ENCRYPTED_APPLICATION, (void *)(pdata+offset), record_hdr.total_len);
				offset+=record_hdr.total_len;
				break;
			case	SSL_CONTENT_TYPE_ALERT:
			case	SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
				offset+=record_hdr.total_len;
				break;
			default:
				offset+=record_hdr.total_len;
				if(per_ss_ctx->identify_pkt_count++>=plugin_env->max_identify_pkt)
				{
					stellar_session_plugin_dettach_current_session(ss);
					return ;
				}
				break;
		}

		if(ret==SSL_DECODER_FALSE)
		{
			break;
		}

		if(ret==SSL_DECODER_CONTINUE)
		{
			//pdata_offset-=5;
			per_ss_ctx->record_trunk.record_hdr=record_hdr;
			per_ss_ctx->record_trunk.is_contains_header=SSL_DECODER_FALSE;
			break;
		}

		pdata_offset+=record_hdr.total_len;
	}

	if(is_trunk_cache(&(per_ss_ctx->record_trunk)) || pdata_sz>pdata_offset)
	{
		ssl_trunk_message_publish(plugin_env, ss, &(per_ss_ctx->record_trunk), pdata+pdata_offset, pdata_sz-pdata_offset);
	}
}

void *ssl_decoder_per_session_context_new(struct session *ss, void *penv)
{
	uint64_t inner_flag=0;
    int32_t ret=session_is_innermost(ss, &inner_flag);
    if(0==ret)
	{
		stellar_session_plugin_dettach_current_session(ss);
        return NULL;
    }

	struct ssl_decoder_context *per_ss_ctx=(struct ssl_decoder_context *)CALLOC(struct ssl_decoder_context, 1);
	per_ss_ctx->record_trunk.is_contains_header=SSL_DECODER_TRUE;
	return (void *)per_ss_ctx;
}

void ssl_decoder_per_session_context_free(struct session *ss, void *per_session_ctx, void *penv)
{
	if(per_session_ctx==NULL)
	{
		return ;
	}

	FREE(per_session_ctx);
}

int32_t ssl_decoder_config_load(const char *cfg_path, struct ssl_decoder_plugin_env *plugin_env)
{
    FILE *fp=fopen(cfg_path, "r");
    if(NULL==fp)
    {
        fprintf(stderr, "[%s:%d] Can't open config file: %s", __FUNCTION__, __LINE__, cfg_path);
        return -1;
    }

    int32_t ret=0;
    char errbuf[256]={0};

    toml_table_t *root=toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    toml_table_t *decoder_tbl=toml_table_in(root, "decoder");
    if(NULL==decoder_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }

    toml_table_t *ssl_tbl=toml_table_in(decoder_tbl, "ssl");
    if(NULL==ssl_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }

	toml_array_t *port_array=toml_array_in(ssl_tbl, "port");
	if(NULL==port_array)
	{
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.port]", __FUNCTION__, __LINE__, cfg_path);
		toml_free(root);
		return -1;
	}

	//toml_array_type
	char port_array_type=toml_array_type(port_array);
	if(port_array_type!='i')
	{
		fprintf(stderr, "[%s:%d] config file: %s key: [decoder.ssl.port] type is not integer", __FUNCTION__, __LINE__, cfg_path);
		toml_free(root);
		return -1;
	}

	plugin_env->n_net_port=toml_array_nelem(port_array);
	plugin_env->net_port=(uint16_t *)CALLOC(uint16_t, plugin_env->n_net_port);
	for(int32_t i=0; i<plugin_env->n_net_port; i++)
	{
		toml_datum_t int_val=toml_int_at(port_array, i);
		if(int_val.ok==0)
		{
			fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.port[%d]]", __FUNCTION__, __LINE__, cfg_path, i);
			ret=-1;
			break;
		}

		plugin_env->net_port[i]=ntohs(int_val.u.i);
	}

    toml_table_t *local_stat_tbl=toml_table_in(ssl_tbl, "local_stat");
    if(NULL==local_stat_tbl)
    {
        fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.local_stat]", __FUNCTION__, __LINE__, cfg_path);
        toml_free(root);
        return -1;
    }

	toml_datum_t stat_interval_time_s_val=toml_int_in(local_stat_tbl, "stat_interval_time_s");
	if(stat_interval_time_s_val.ok==0)
	{
		plugin_env->stat.interval_second=5;
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.local_stat.stat_interval_time_s]", __FUNCTION__, __LINE__, cfg_path);
	}
	else
	{
		plugin_env->stat.interval_second=stat_interval_time_s_val.u.i;
	}

	toml_datum_t stat_per_thread_enable_val=toml_string_in(local_stat_tbl, "stat_per_thread_enable");
	if(stat_per_thread_enable_val.ok==0)
	{
		plugin_env->stat.per_thread_enable=SSL_DECODER_FALSE;
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.local_stat.stat_per_thread_enable]", __FUNCTION__, __LINE__, cfg_path);
	}
	else
	{
		if(memcmp("no", stat_per_thread_enable_val.u.s, strlen("no"))==0)
		{
			plugin_env->stat.per_thread_enable=SSL_DECODER_FALSE;
		}
		else if(memcmp("yes", stat_per_thread_enable_val.u.s, strlen("yes"))==0)
		{
			plugin_env->stat.per_thread_enable=SSL_DECODER_TRUE;
		}
		else
		{
			plugin_env->stat.per_thread_enable=SSL_DECODER_FALSE;
			fprintf(stderr, "[%s:%d] config file: %s key: [decoder.ssl.local_stat.stat_per_thread_enable] value is not yes or no", __FUNCTION__, __LINE__, cfg_path);
		}
	}

	toml_datum_t name=toml_string_in(local_stat_tbl, "stat_name");
	if(name.ok==0)
	{
		memcpy(plugin_env->stat.name, "ssl_DECODER", MIN(sizeof(plugin_env->stat.name)-1, strlen("ssl_DECODER")));
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.local_stat.stat_name]", __FUNCTION__, __LINE__, cfg_path);
	}
	else
	{
		strncpy(plugin_env->stat.name, name.u.s, sizeof(plugin_env->stat.name));
	}

	toml_datum_t output_path=toml_string_in(local_stat_tbl, "stat_output");
	if(output_path.ok==0)
	{
		memcpy(plugin_env->stat.path, "metrics/ssl_decoder_local_stat.json", MIN(sizeof(plugin_env->stat.path)-1, strlen("metrics/ssl_decoder_local_stat.json")));
		fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.local_stat.stat_output]", __FUNCTION__, __LINE__, cfg_path);
	}
	else
	{
		strncpy(plugin_env->stat.path, output_path.u.s, sizeof(plugin_env->stat.path));
	}

	toml_free(root);
	
    return ret;
}

void ssl_decoder_local_file_stat_init(struct ssl_decoder_plugin_env *plugin_env)
{
    // if(plugin_env->stat.interval_second==0)
    // {
    //     printf("ssl_decoder_local_file_stat_init, Disable local stat, name: %s output: %s", plugin_env->stat.name, plugin_env->stat.path);
    //     return ;
    // }

    // plugin_env->stat.fse=fieldstat_easy_new(stellar_get_worker_thread_num(plugin_env->st), plugin_env->stat.name, NULL, 0);
    // if(plugin_env->stat.fse==NULL)
    // {
    //     printf("ssl_decoder_local_file_stat_init, fieldstat_easy_new failed, name: %s output: %s", plugin_env->stat.name, plugin_env->stat.path);
    //     exit(-1);
    // }

    // fieldstat_easy_enable_auto_output(plugin_env->stat.fse, plugin_env->stat.path, plugin_env->stat.interval_second);

    // const char *local_stat_name[LOCAL_STAT_COUNTER_MAX]={0};
    // local_stat_name[LOCAL_STAT_COUNTER_UNKNOWN]="unknown";
	// local_stat_name[LOCAL_STAT_COUNTER_SESSION]="session";
    // local_stat_name[LOCAL_STAT_COUNTER_PACKETS]="packets";
    // local_stat_name[LOCAL_STAT_COUNTER_BYTES]="bytes";
	// local_stat_name[LOCAL_STAT_COUNTER_SEND]="send";
	// local_stat_name[LOCAL_STAT_COUNTER_RECV]="recv";
	// local_stat_name[LOCAL_STAT_COUNTER_NEW]="new";
	// local_stat_name[LOCAL_STAT_COUNTER_FREE]="free";
	// local_stat_name[LOCAL_STAT_COUNTER_OK]="ok";
	// local_stat_name[LOCAL_STAT_COUNTER_ERROR]="error";


    // plugin_env->stat.metric_id=(int32_t *)CALLOC(int, LOCAL_STAT_COUNTER_MAX);
    // for(int32_t i=0; i<LOCAL_STAT_COUNTER_MAX; i++)
    // {
    //     plugin_env->stat.metric_id[i]=fieldstat_easy_register_counter(plugin_env->stat.fse, local_stat_name[i]);
    //     if(plugin_env->stat.metric_id[i]<0)
    //     {
    //         printf("ssl_decoder_local_file_stat_init, fieldstat_easy_register_counter failed, name: %s", local_stat_name[i]);
    //         exit(-1);
    //     }
    // }
}

extern "C" void *ssl_decoder_init(struct stellar *st)
{
    struct ssl_decoder_plugin_env *plugin_env=CALLOC(struct ssl_decoder_plugin_env, 1);
    plugin_env->st=st;

    plugin_env->plugin_id=stellar_session_plugin_register(st, ssl_decoder_per_session_context_new, ssl_decoder_per_session_context_free, plugin_env);
    if(plugin_env->plugin_id<0) 
	{
		printf("ssl_decoder_init: stellar_session_plugin_register failed\n");
        exit(0);
    }

	ssl_decoder_config_load(SSL_DECODER_TOML_PATH, plugin_env);
	ssl_decoder_local_file_stat_init(plugin_env);

	plugin_env->ssl.free_cb=ssl_message_free;
	plugin_env->ssl.on_cb=NULL;
	plugin_env->ssl.topic_name=SSL_DECODER_MESSAGE_TOPIC;
    plugin_env->ssl.topic_id=stellar_session_mq_get_topic_id(plugin_env->st, plugin_env->ssl.topic_name);
    if(plugin_env->ssl.topic_id<0)
	{
        plugin_env->ssl.topic_id=stellar_session_mq_create_topic(plugin_env->st, plugin_env->ssl.topic_name, ssl_message_free, NULL);
    }

	plugin_env->ptrunk.free_cb=ssl_trunk_message_free;
	plugin_env->ptrunk.on_cb=NULL;
	plugin_env->ptrunk.topic_name=SSL_TRUNK_MESSAGE_TOPIC;
	plugin_env->ptrunk.topic_id=stellar_session_mq_get_topic_id(plugin_env->st, plugin_env->ptrunk.topic_name);
	if(plugin_env->ptrunk.topic_id<0)
	{
		plugin_env->ptrunk.topic_id=stellar_session_mq_create_topic(plugin_env->st, plugin_env->ptrunk.topic_name, ssl_trunk_message_free, NULL);
	}

	plugin_env->strunk.free_cb=NULL;
	plugin_env->strunk.on_cb=ssl_trunk_message_segment_data_cb;
	plugin_env->strunk.topic_name=SSL_TRUNK_MESSAGE_TOPIC;
	plugin_env->strunk.topic_id=stellar_session_mq_get_topic_id(plugin_env->st, plugin_env->strunk.topic_name);
	plugin_env->strunk.sub_id=stellar_session_mq_subscribe(plugin_env->st, plugin_env->strunk.topic_id, plugin_env->strunk.on_cb, plugin_env->plugin_id);

	plugin_env->tcp_stream.free_cb=NULL;
	plugin_env->tcp_stream.on_cb=ssl_tcp_stream_session_segment_data_cb;
	plugin_env->tcp_stream.topic_name=TOPIC_TCP_STREAM;
	plugin_env->tcp_stream.topic_id=stellar_session_mq_get_topic_id(plugin_env->st, plugin_env->tcp_stream.topic_name);
	plugin_env->tcp_stream.sub_id=stellar_session_mq_subscribe(plugin_env->st, plugin_env->tcp_stream.topic_id, plugin_env->tcp_stream.on_cb, plugin_env->plugin_id);

    printf("ssl_decoder_init: plugin_id: %d, topic: [{name: %s -> id: %d}, {name: %s -> id: %d}, {name: %s -> id: %d}, {name: %s -> id: %d}] \n",
			plugin_env->plugin_id, 
			plugin_env->ssl.topic_name, plugin_env->ssl.topic_id,
			plugin_env->ptrunk.topic_name, plugin_env->ptrunk.topic_id,
			plugin_env->strunk.topic_name, plugin_env->strunk.topic_id,
			plugin_env->tcp_stream.topic_name, plugin_env->tcp_stream.topic_id
		);

    return plugin_env;
}

extern "C" void ssl_decoder_exit(void *penv)
{
    if(NULL==penv) 
	{
        return;
    }

    struct ssl_decoder_plugin_env *plugin_env=(struct ssl_decoder_plugin_env *)penv;
    if(plugin_env->ssl.topic_id>=0) 
	{
        stellar_session_mq_destroy_topic(plugin_env->st, plugin_env->ssl.topic_id);
    	plugin_env->ssl.topic_id=-1;
    }

	if(plugin_env->tcp_stream.topic_id>=0)
	{
		stellar_session_mq_destroy_topic(plugin_env->st, plugin_env->tcp_stream.topic_id);
		plugin_env->tcp_stream.topic_id=-1;
	}

    FREE(penv);
}
