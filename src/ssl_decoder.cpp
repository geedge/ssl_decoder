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

#define SSL_DECODER_FALSE 0
#define SSL_DECODER_TRUE 1

#define SSL_UUID_BYTES_SZ   16

#define SSL_RANDOM_TIME_LEN 4
#define SSL_RANDOM_SIZE		28

#define SSL_HANDSHAKE_CLIENT_HELLO	1
#define SSL_HANDSHAKE_SERVER_HELLO	2
#define SSL_HANDSHAKE_CERTIFICATE	11
#define SSL_HANDSHAKE_SERVER_KEY_EXCHANGE	12

#define	SSL_CONTENT_TYPE_HANDSHAKE	0x16
#define	SSL_CONTENT_TYPE_ALERT		0x15
#define	SSL_CONTENT_TYPE_APPLICATION_DATA	0x17
#define	SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC	0x14

#define ALPN_EXT_TYPE					0x0010
#define SERVER_NAME_EXT_TYPE			0x0000
#define SERVER_NAME_HOST_TYPE 			0x0000
#define SERVER_NAME_OTHER_TYPE 			0x0008
#define SESSION_TICKET_EXT_TYPE 		0x0023
#define ENCRPTED_SERVER_NAME_EXT_TYPE	0xFFCE
#define ENCRPTED_CLIENT_HELLO_EXT_TYPE	0xFE0D
#define	EC_POINT_FORMATS_EXT_TYPE		0x000B

// https://datatracker.ietf.org/doc/html/rfc7919
// Supported Groups
#define SUPPORTED_GROUPS_EXT_TYPE		0x000A

#define	SSL_DECODER_TOML_PATH	"conf/ssl/ssl_decoder.toml"

UT_icd UT_ssl_hello_extension_icd={sizeof(struct ssl_decoder_ltv), NULL, NULL, NULL};

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
	struct ssl_record_header header;
	size_t cache_len;
	uint8_t* cache_buff;
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
	struct message_schema tcp_stream;
	struct ssl_decoder_stat stat;
};

struct ssl_decoder_context
{
	int32_t identify_pkt_count;
    struct ssl_record_trunk record_trunk;
};

struct ssl_message 
{
	int32_t magic;
    enum ssl_message_type type;
	char uuid_bytes[SSL_UUID_BYTES_SZ];
	struct session *ss;
	struct ssl_decoder_plugin_env *plugin_env;
};

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
	if ((val & 0x0f)!=0x0a)
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
        if(record_trunk->cache_buff!=NULL)
        {
            FREE(record_trunk->cache_buff);
            record_trunk->cache_buff=NULL;
        }

        record_trunk={0};
    }
}

void ssl_trunk_cache(struct ssl_record_trunk *record_trunk, uint8_t *fragment, size_t fragment_sz)
{
	if(fragment==NULL || fragment_sz==0)
	{
		return ;
	}

    if(record_trunk->cache_buff==NULL)
    {
        record_trunk->cache_buff=(uint8_t *)malloc(fragment_sz);
    }

    memmove(record_trunk->cache_buff+record_trunk->cache_len, fragment, fragment_sz);
    record_trunk->cache_len+=fragment_sz;
}

int32_t is_trunk_cache(struct ssl_record_trunk *record_trunk)
{
    return ((record_trunk->cache_len>0) ? SSL_DECODER_TRUE : SSL_DECODER_FALSE);
}

void ssl_recod_buff_get0(struct ssl_record_trunk *record_trunk, uint8_t **record_buff, size_t *record_buff_sz)
{
    if(!is_trunk_cache(record_trunk) || (*record_buff_sz)<=SSL_RECORD_HEADER_SZ)
    {
        return ;
    }

    ssl_trunk_cache(record_trunk, (*record_buff), (*record_buff_sz));

    (*record_buff)=record_trunk->cache_buff;
    (*record_buff_sz)=record_trunk->cache_len;
}

void ssl_handshake_certificate_decode()
{

}

void ssl_handshake_server_key_exchange_decode()
{

}


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
	int32_t total_len; //3
	int32_t ret=ssl_read_be_u24(pdata, pdata_sz, pdata_offset, (uint8_t *)&(total_len));
	if(total_len<0) /*CLIENT_HELLO_HDRLEN: 4 means client_type+len*/
	{
		return NULL;
	}

	struct ssl_server_hello *shello=(struct ssl_server_hello *)CALLOC(struct ssl_server_hello, 1);
	ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(shello->version));
	ssl_read_be_u32(pdata, pdata_sz, pdata_offset, &(shello->random_gmt_time));

	for(int i=1; i<SSL_HELLO_LTV_MAX; i++)
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
	int32_t total_len; //3
	int32_t ret=ssl_read_be_u24(pdata, pdata_sz, pdata_offset, (uint8_t *)&(total_len));
	if(total_len<0) /*CLIENT_HELLO_HDRLEN: 4 means client_type+len*/
	{
		return NULL;
	}

	struct ssl_client_hello *chello=(struct ssl_client_hello *)CALLOC(struct ssl_client_hello, 1);
	ssl_read_be_u16(pdata, pdata_sz, pdata_offset, &(chello->version));
	ssl_read_be_u32(pdata, pdata_sz, pdata_offset, &(chello->random_gmt_time));

	for(int i=1; i<SSL_HELLO_LTV_MAX; i++)
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

		switch(ltv.type)
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

void ssl_handshake_decode(struct ssl_decoder_plugin_env *plugin_env, struct session *ss, uint8_t *segment_buff, size_t segment_buff_sz, size_t *segment_buff_offset)
{
	if(segment_buff==NULL || ((*segment_buff_offset)+1>segment_buff_sz))
	{
		return ;
	}

	struct ssl_client_hello *chello=NULL;
	struct ssl_server_hello *shello=NULL;
	struct ssl_handshake_type *handshake_type=(struct ssl_handshake_type *)(segment_buff+(*segment_buff_offset));
	(*segment_buff_offset)+=sizeof(struct ssl_handshake_type);
	switch(handshake_type->content_type)
	{
		case	SSL_HANDSHAKE_CLIENT_HELLO:
			chello=ssl_handshake_client_hello_decode(segment_buff, segment_buff_sz, segment_buff_offset);
			ssl_client_hello_ja3_generate(chello);
			break;
		case	SSL_HANDSHAKE_SERVER_HELLO:
			shello=ssl_handshake_server_hello_decode(segment_buff, segment_buff_sz, segment_buff_offset);
			ssl_server_hello_ja3s_generate(shello);
			break;
		case	SSL_HANDSHAKE_CERTIFICATE:
			// ssl_handshake_certificate_decode();
			break;
		case	SSL_HANDSHAKE_SERVER_KEY_EXCHANGE:
			// ssl_handshake_server_key_exchange_decode();
			break;
		default:
			break;
	}
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


void ssl_tcp_stream_session_segment_data_cb(struct session *ss, int32_t topic_id, const void *msg, void *per_session_ctx, void *penv)
{
	size_t segment_buff_offset=0;
    size_t segment_buff_sz=0;
    uint8_t *segment_buff=NULL;
    segment_buff=(uint8_t *)session_get0_current_payload(ss, &segment_buff_sz);
    if(segment_buff_sz==0 || segment_buff==NULL)
    {
        return ;
    }

    /*
    * fragment:
        1: less than SSL_RECORD_HEADER_SZ
        2: less than the length of the message
    */

    struct ssl_decoder_context *per_ss_ctx=(struct ssl_decoder_context *)(per_session_ctx);

    ssl_recod_buff_get0(&(per_ss_ctx->record_trunk), &segment_buff, &segment_buff_sz);
    if(segment_buff_sz<=SSL_RECORD_HEADER_SZ)
    {
        return ;
    }

	struct ssl_record_header record_hdr={0};
	ssl_record_header_get(&record_hdr, segment_buff, segment_buff_sz, &segment_buff_offset);
	if(!is_trunk_cache(&(per_ss_ctx->record_trunk)) && segment_buff_sz<record_hdr.total_len)
	{
		ssl_trunk_cache(&(per_ss_ctx->record_trunk), segment_buff, segment_buff_sz);
		return ;
	}

	struct ssl_decoder_plugin_env *plugin_env=(struct ssl_decoder_plugin_env *)penv;

	switch(record_hdr.content_type)
	{
		case	SSL_CONTENT_TYPE_HANDSHAKE:
			ssl_handshake_decode(plugin_env, ss, segment_buff, segment_buff_sz, &segment_buff_offset);
			break;
		case	SSL_CONTENT_TYPE_ALERT:
			break;
		case	SSL_CONTENT_TYPE_APPLICATION_DATA:
			break;
		case	SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
			break;
		default:
			if(per_ss_ctx->identify_pkt_count++>=plugin_env->max_identify_pkt)
			{
				stellar_session_plugin_dettach_current_session(ss);
				return ;
			}
			break;
	}
}

void ssl_message_free(struct session *sess, void *msg, void *msg_free_arg)
{

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

	return CALLOC(struct ssl_decoder_context, 1);
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
    if (NULL==fp)
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

    // toml_table_t *limited_tbl=toml_table_in(ssl_tbl, "limited");
    // if(NULL==limited_tbl)
    // {
    //     fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.limited]", __FUNCTION__, __LINE__, cfg_path);
    //     toml_free(root);
    //     return -1;
    // }

	// toml_datum_t max_rr_num_val=toml_int_in(limited_tbl, "max_rr_num");
	// if(max_rr_num_val.ok==0)
	// {
	// 	fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.limited.max_rr_num]", __FUNCTION__, __LINE__, cfg_path);
	// 	ret=-1;
	// }
	// else
	// {
	// 	plugin_env->max_rr_num=max_rr_num_val.u.i;
	// }

	// // max_cache_trans_num
	// toml_datum_t max_cache_trans_num_val=toml_int_in(limited_tbl, "max_cache_trans_num");
	// if(max_cache_trans_num_val.ok==0)
	// {
	// 	fprintf(stderr, "[%s:%d] config file: %s has no key: [decoder.ssl.limited.max_cache_trans_num]", __FUNCTION__, __LINE__, cfg_path);
	// 	ret=-1;
	// }
	// else
	// {
	// 	plugin_env->max_cache_trans_num=max_cache_trans_num_val.u.i;
	// }

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
    plugin_env->ssl.topic_id=stellar_session_mq_get_topic_id(st, plugin_env->ssl.topic_name);
    if(plugin_env->ssl.topic_id<0)
	{
        plugin_env->ssl.topic_id=stellar_session_mq_create_topic(st, plugin_env->ssl.topic_name, ssl_message_free, NULL);
    }

	plugin_env->tcp_stream.free_cb=NULL;
	plugin_env->tcp_stream.on_cb=ssl_tcp_stream_session_segment_data_cb;
	plugin_env->tcp_stream.topic_name=TOPIC_TCP_STREAM;
	plugin_env->tcp_stream.topic_id=stellar_session_mq_get_topic_id(plugin_env->st, plugin_env->tcp_stream.topic_name);
	plugin_env->tcp_stream.sub_id=stellar_session_mq_subscribe(plugin_env->st, plugin_env->tcp_stream.topic_id, plugin_env->tcp_stream.on_cb, plugin_env->plugin_id);

    printf("ssl_decoder_init: plugin_id: %d, topic: [{name: %s -> id: %d}, {name: %s -> id: %d}] \n",
			plugin_env->plugin_id, 
			plugin_env->ssl.topic_name, plugin_env->ssl.topic_id,
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
