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

   return ((msg->chello->esni==NULL) ? 1 : 0);
}

int32_t ssl_message_ech_is_true(const struct ssl_message *msg)
{
    if(msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CLIENT_HELLO)
    {
        return -1;
    }

    return ((msg->chello->ech==NULL) ? 1 : 0);
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
        default:
            return NULL;
    }

    switch(version)
    {
        case SSL_DECODER_VERSION_SSL_V2_0:
            return "SSLv2.0";
        case SSL_DECODER_VERSION_SSL_V3_0:
            return "SSLv3.0";
        case SSL_DECODER_VERSION_TLS_V1_0:
            return "TLSv1.0";
        case SSL_DECODER_VERSION_TLS_V1_1:
            return "TLSv1.1";
        case SSL_DECODER_VERSION_TLS_V1_2:
            return "TLSv1.2";
        case SSL_DECODER_VERSION_TLS_V1_3:
            return "TLSv1.3";
        case SSL_DECODER_VERSION_TLCP_V1_0:
            return "TLCPv1.0";
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
    return ((msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE) ? msg->certificate->type : SSL_CERTIFICATE_TYPE_UNKNOWN);
}

void ssl_message_validity_before_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

void ssl_message_validity_after_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

void ssl_message_issuer_serial_number_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

void ssl_message_subject_public_key_algorithm_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

void ssl_message_ssl_algorithm_identifier_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

void ssl_message_ssl_signature_algorithm_id_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

void ssl_message_subject_alter_next(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}

int ssl_message_reset_subject_alter_iter(struct ssl_message *msg)
{
    return 0;
}

struct ssl_rdn_sequence *ssl_message_issuer_rdn_sequence_get0(const struct ssl_message *msg)
{
    return ((msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE) ? &(msg->certificate->issuer) : NULL);
}

struct ssl_rdn_sequence *ssl_message_subject_rdn_sequence_get0(const struct ssl_message *msg)
{
    return ((msg==NULL || msg->magic!=SSL_MESSAGE_MAGIC || msg->type!=SSL_MESSAGE_CERTIFICATE) ? &(msg->certificate->subject) : NULL);
}

void ssl_rdn_sequence_common_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_country_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_locality_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_postal_code_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_organization_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_street_address_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_state_or_province_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_organizational_unit_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_rdn_sequence_list_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz)
{

}

void ssl_message_protected_payload_get0(const struct ssl_message *msg, char **value, size_t *value_sz)
{

}