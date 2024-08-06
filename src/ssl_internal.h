#pragma once

#include <stdint.h>
#include <stddef.h>

#include <uthash/utarray.h>

#define SSL_DECODER_VERSION_UNKNOWN		0x0000
#define SSL_DECODER_VERSION_SSL_V2_0	0x0002
#define SSL_DECODER_VERSION_SSL_V3_0	0x0300
#define SSL_DECODER_VERSION_TLS_V1_0	0x0301
#define SSL_DECODER_VERSION_TLS_V1_1	0x0302
#define SSL_DECODER_VERSION_TLS_V1_2	0x0303
#define SSL_DECODER_VERSION_TLS_V1_3	0x0304
#define SSL_DECODER_VERSION_TLCP_V1_0	0x0101

#define	SSL_DECODER_NONE	0x00
#define	SSL_DECODER_L1V		0x01
#define	SSL_DECODER_L2V		0x02
#define	SSL_DECODER_L2TV	0x03

struct ssl_decoder_ltv
{
	uint16_t type;	// marco SSL_DECODER*
	uint16_t vtype;
	union
	{
		uint8_t lv_u8;
		uint16_t lv_u16;
		uint32_t lv_u32;
	};

	uint8_t *value;
};

enum SSL_HELLO_LTV
{
	SSL_HELLO_LTV_UNKNOWN=0,	
	SSL_HELLO_LTV_RANDOM_BYTES,
	SSL_HELLO_LTV_SESSION,
	SSL_HELLO_LTV_CIPERSUITES,
	SSL_HELLO_LTV_COMPRESS_METHOD,
	SSL_HELLO_LTV_MAX,
};

struct ssl_client_hello
{
	uint16_t version;
	uint32_t random_gmt_time;
	
	UT_array *extensions;
	struct ssl_decoder_ltv ja3;
	struct ssl_decoder_ltv *sni;
	struct ssl_decoder_ltv *ech;
	struct ssl_decoder_ltv *esni;
	struct ssl_decoder_ltv ltv[SSL_HELLO_LTV_MAX];
};

struct ssl_server_hello
{
	uint16_t version;
	uint32_t random_gmt_time;
	
	UT_array *extensions;
	struct ssl_decoder_ltv ja3s;
	struct ssl_decoder_ltv ltv[SSL_HELLO_LTV_MAX];
};

struct ssl_new_session_ticket
{
	int total_len;	//3 bytes
	int lift_time;	//second
	int ticket_len;	//3 bytes
	unsigned char* ticket;
};

#define MAX_ALTER_NAME_LEN		64
struct ssl_subject_alter_name
{
	int num;
	char (*name)[MAX_ALTER_NAME_LEN];
};

#define MAX_RDN_SEQUENCE_LEN		64
#define MAX_RDN_SEQUENCE_LIST_LEN	512
struct ssl_rdn_sequence
{
	char common[MAX_RDN_SEQUENCE_LEN];				//commonName
	char country[MAX_RDN_SEQUENCE_LEN];				//countryName
	char locality[MAX_RDN_SEQUENCE_LEN];				//localityName
	char postal_code[MAX_RDN_SEQUENCE_LEN];			// postalCode
	char organization[MAX_RDN_SEQUENCE_LEN];			//organizationName
	char street_address[MAX_RDN_SEQUENCE_LEN];		//streetAddress
	char state_or_Province[MAX_RDN_SEQUENCE_LEN];		//stateOrProvinceName
	char organizational_unit[MAX_RDN_SEQUENCE_LEN];	//organizationalUnitName
	char rdn_sequence_list[MAX_RDN_SEQUENCE_LIST_LEN];  //commonName +  organizationName + organizationalUnitName + localityName + streetAddress + stateOrProvinceName + countryName	
};

#define	MAX_VALIDITY_LEN	80
struct ssl_validity
{
	char before[MAX_VALIDITY_LEN];
	char after[MAX_VALIDITY_LEN];
};

struct ssl_subject_public_key
{
	int len;
	char*value;
};

#define MAX_SERIAL_NUMBER_LEN	128
struct ssl_serial_number
{
	unsigned char len;
	char value[MAX_SERIAL_NUMBER_LEN];
};

#define MAX_SIGNATURE_ALGORITHM_ID_LEN	64
struct ssl_signature_algorithm_id
{
	unsigned char len;
	char value[MAX_SIGNATURE_ALGORITHM_ID_LEN];
};

#define MAX_ALGORITHM_IDENTIFIER	64
struct ssl_algorithm_identifier
{
	unsigned char len;
	char value[MAX_ALGORITHM_IDENTIFIER];
};

struct ssl_certificate
{
	int total_len;
	int cert_len;
	char cert_type;
	
	//struct ssl_l1v version;
	struct ssl_validity validity;
	struct ssl_serial_number serial;
	struct ssl_rdn_sequence issuer;
	struct ssl_rdn_sequence subject;
	
	struct ssl_subject_public_key subject_key;
	struct ssl_subject_alter_name subject_alter;
	struct ssl_algorithm_identifier algorithm_identifier;
	struct ssl_signature_algorithm_id signature_algorithm;
};
