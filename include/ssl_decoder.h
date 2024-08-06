#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>

#define SSL_DECODER_MESSAGE_TOPIC "SSL_DECODER_MESSAGE"

enum ssl_message_type
{
    SSL_MESSAGE_CLIENT_HELLO,
    SSL_MESSAGE_SERVER_HELLO,
    SSL_MESSAGE_CERTIFICATE,
    SSL_PROTECTED_PAYLOAD,
    SSL_MSG_MAX,
};

struct ssl_message;
enum ssl_message_type ssl_message_type_get(const struct ssl_message *msg);

// SSL_MESSAGE_CLIENT_HELLO
int32_t ssl_message_esni_is_true(const struct ssl_message *msg);
int32_t ssl_message_ech_is_true(const struct ssl_message *msg);

void ssl_message_sni_get0(const struct ssl_message *msg, char **value, size_t *value_sz);
void ssl_message_ja3hash_get0(const struct ssl_message *msg, char **value, size_t *value_sz);

const char *ssl_message_readable_version_get0(const struct ssl_message *msg);

// SSL_MESSAGE_SERVER_HELLO
void ssl_message_ja3shash_get0(const struct ssl_message *msg, char **value, size_t *value_sz);

void ssl_message_extensions_next(const struct ssl_message *msg, char **value, size_t *value_sz);
int ssl_message_reset_extensions_iter(struct ssl_message *msg);

// SSL_MESSAGE_CERTIFICATE
enum ssl_certificate_type
{
    SSL_CERTIFICATE_TYPE_UNKNOWN=0,
    SSL_CERTIFICATE_TYPE_INDIVIDUAL,
    SSL_CERTIFICATE_TYPE_ROOT,
    SSL_CERTIFICATE_TYPE_MIDDLE,
    SSL_CERTIFICATE_TYPE_CHAIN,
    SSL_CERTIFICATE_TYPE_MAX,
};

enum ssl_certificate_type ssl_certificate_type_get(const struct ssl_message *msg);
void ssl_message_validity_before_get0(const struct ssl_message *msg, char **value, size_t *value_sz);
void ssl_message_validity_after_get0(const struct ssl_message *msg, char **value, size_t *value_sz);
void ssl_message_issuer_serial_number_get0(const struct ssl_message *msg, char **value, size_t *value_sz);
void ssl_message_subject_public_key_algorithm_get0(const struct ssl_message *msg, char **value, size_t *value_sz);
void ssl_message_ssl_algorithm_identifier_get0(const struct ssl_message *msg, char **value, size_t *value_sz);
void ssl_message_ssl_signature_algorithm_id_get0(const struct ssl_message *msg, char **value, size_t *value_sz);

/**
 * @brief loop reading all domain of subject_alter.
 * 
*/

void ssl_message_subject_alter_next(const struct ssl_message *msg, char **value, size_t *value_sz);
/**
 * @retval succeed( >= 0) failed(-1)
*/
int ssl_message_reset_subject_alter_iter(struct ssl_message *msg);

struct ssl_rdn_sequence;
struct ssl_rdn_sequence *ssl_message_issuer_rdn_sequence_get0(const struct ssl_message *msg);
struct ssl_rdn_sequence *ssl_message_subject_rdn_sequence_get0(const struct ssl_message *msg);

void ssl_rdn_sequence_common_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_country_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_locality_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_postal_code_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_organization_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_street_address_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_state_or_province_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_organizational_unit_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);
void ssl_rdn_sequence_list_get0(struct ssl_rdn_sequence *rdn, char **value, size_t *value_sz);

// SSL_PROTECTED_PAYLOAD
void ssl_message_protected_payload_get0(const struct ssl_message *msg, char **value, size_t *value_sz);

#ifdef __cplusplus
}
#endif

