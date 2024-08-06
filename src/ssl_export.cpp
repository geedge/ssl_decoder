#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssl_internal.h"
#include "ssl_decoder.h"

enum ssl_message_type ssl_message_type_get(const struct ssl_message *msg)
{
    return ((msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC) ? SSL_MSG_MAX : msg->type);
}

// SSL_MESSAGE_CLIENT_HELLO
int32_t ssl_message_esni_is_true(const struct ssl_message *msg)
{
   if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CLIENT_HELLO)
   {
        return -1;
   }

   return ((msg->chello->esni==NULL) ? 0 : 1);
}

int32_t ssl_message_ech_is_true(const struct ssl_message *msg)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CLIENT_HELLO)
    {
        return -1;
    }

    return ((msg->chello->ech==NULL) ? 0 : 1);
}

void ssl_message_sni_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CLIENT_HELLO)
    {
        return;
    }

    if(msg->chello->sni==NULL)
    {
        return;
    }

    *value=(char *)msg->chello->sni->value;
    *value_sz=msg->chello->sni->lv_u32;
}

const char *ssl_message_readable_version_get0(const struct ssl_message *msg)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC)
    {
        return NULL;
    }

    uint16_t version=0;
    switch(msg->type)
    {
        case    SSL_MESSAGE_CLIENT_HELLO:
            if(msg->chello==NULL)
            {
                return NULL;
            }
            version=msg->chello->version;
            break;
        case    SSL_MESSAGE_SERVER_HELLO:
            if(msg->shello==NULL)
            {
                return NULL;
            }
            version=msg->shello->version;
            break;
        case    SSL_MESSAGE_CERTIFICATE:
            if(msg->certificate==NULL)
            {
                return NULL;
            }

            switch(msg->certificate->version)
            {
                case    0:
                    return "v1";
                case    1:
                    return "v2";
                case    2:
                    return "v3";
                case    3:
                    return "v4";
                default:
                    break;
            }
            return NULL;
        default:
            return NULL;
    }

    switch(version)
    {
        case SSL_DECODER_VERSION_SSL_V2_0:
            return "SSL2.0";
        case SSL_DECODER_VERSION_SSL_V3_0:
            return "SSL3.0";
        case SSL_DECODER_VERSION_TLS_V1_0:
            return "TLS1.0";
        case SSL_DECODER_VERSION_TLS_V1_1:
            return "TLS1.1";
        case SSL_DECODER_VERSION_TLS_V1_2:
            return "TLS1.2";
        case SSL_DECODER_VERSION_TLS_V1_3:
            return "TLS1.3";
        case SSL_DECODER_VERSION_TLCP_V1_0:
            return "TLCP1.0";
        default:
            break;
    }

    return NULL;
}

void ssl_message_ja3hash_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CLIENT_HELLO)
    {
        *value=NULL;
        *value_sz=0;
        return ;
    }

    if(msg->chello->ja3.value==NULL || msg->chello->ja3.lv_u32==0)
    {
        *value=NULL;
        *value_sz=0;
        return ;
    }

    *value=(char *)msg->chello->ja3.value;
    *value_sz=msg->chello->ja3.lv_u32;
}

// SSL_MESSAGE_SERVER_HELLO
void ssl_message_ja3shash_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_SERVER_HELLO)
    {
        *value=NULL;
        *value_sz=0;
        return;
    }

    if(msg->shello->ja3s.value==NULL || msg->shello->ja3s.lv_u32==0)
    {
        *value=NULL;
        *value_sz=0;
        return;
    }

    *value=(char *)msg->shello->ja3s.value;
    *value_sz=msg->shello->ja3s.lv_u32;
}

void ssl_message_extensions_next(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

int ssl_message_reset_extensions_iter(struct ssl_message *msg)
{
    return 0;
}

enum ssl_certificate_type ssl_certificate_type_get(const struct ssl_message *msg)
{
    return ((msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE) ? SSL_CERTIFICATE_TYPE_UNKNOWN : msg->certificate->type);
}

void ssl_message_validity_before_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return;
    }

    *value=(char *)msg->certificate->validity.before;
    *value_sz=strlen(msg->certificate->validity.before);
}

void ssl_message_validity_after_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return;
    }

    *value=(char *)msg->certificate->validity.after;
    *value_sz=strlen(msg->certificate->validity.after);
}

void ssl_message_issuer_serial_number_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return;
    }

    *value=(char *)msg->certificate->serial.value;
    *value_sz=msg->certificate->serial.len;
}

void ssl_message_subject_public_key_algorithm_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return;
    }

    *value=(char *)msg->certificate->subject_key.value;
    *value_sz=msg->certificate->subject_key.len;
}

void ssl_message_algorithm_identifier_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return;
    }

    *value=(char *)msg->certificate->algorithm_identifier.value;
    *value_sz=msg->certificate->algorithm_identifier.len;
}

void ssl_message_signature_algorithm_id_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return;
    }

    *value=(char *)msg->certificate->signature_algorithm.value;
    *value_sz=msg->certificate->signature_algorithm.len;
}

void ssl_message_subject_alter_next(const struct ssl_message *msg, char **value, size_t *value_sz)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return;
    }

    if(msg->certificate->subject_alter.num==0 || msg->certificate->subject_alter.offset>=msg->certificate->subject_alter.num)
    {
        *value=NULL;
        *value_sz=0;
        return;
    }

    *value=(char *)msg->certificate->subject_alter.name[msg->certificate->subject_alter.offset];
    *value_sz=strlen(msg->certificate->subject_alter.name[msg->certificate->subject_alter.offset]);
    msg->certificate->subject_alter.offset++;
}

int ssl_message_reset_subject_alter_iter(struct ssl_message *msg)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE)
    {
        return -1;
    }

    msg->certificate->subject_alter.offset=0;
    return 0;
}

struct ssl_rdn_sequence *ssl_message_issuer_rdn_sequence_get0(const struct ssl_message *msg)
{
    return ((msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE) ? NULL : &(msg->certificate->issuer));
}

struct ssl_rdn_sequence *ssl_message_subject_rdn_sequence_get0(const struct ssl_message *msg)
{
    return ((msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE) ? NULL : &(msg->certificate->subject));
}

void ssl_rdn_sequence_common_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->common);
    *value=(((*value_sz)>0) ? rdn->common : NULL);
}

void ssl_rdn_sequence_country_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->country);
    *value=(((*value_sz)>0) ? rdn->country : NULL);
}

void ssl_rdn_sequence_locality_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->locality);
    *value=(((*value_sz)>0) ? rdn->locality : NULL);
}

void ssl_rdn_sequence_postal_code_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->postal_code);
    *value=(((*value_sz)>0) ? rdn->postal_code : NULL);
}

void ssl_rdn_sequence_organization_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->organization);
    *value=(((*value_sz)>0) ? rdn->organization : NULL);
}

void ssl_rdn_sequence_street_address_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->street_address);
    *value=(((*value_sz)>0) ? rdn->street_address : NULL);
}

void ssl_rdn_sequence_state_or_province_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->state_or_Province);
    *value=(((*value_sz)>0) ? rdn->state_or_Province : NULL);
}

void ssl_rdn_sequence_organizational_unit_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->organizational_unit);
    *value=(((*value_sz)>0) ? rdn->organizational_unit : NULL);
}

void ssl_rdn_sequence_list_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{
    if(rdn==NULL)
    {
        return;
    }

    *value_sz=strlen(rdn->rdn_sequence_list);
    *value=(((*value_sz)>0) ? rdn->rdn_sequence_list : NULL);
}

void ssl_message_protected_payload_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}