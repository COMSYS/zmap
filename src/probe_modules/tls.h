#ifndef TLS_H
#define TLS_H 1

#define TLS_ALERT 21
#define TLS_HANDSHAKE 22
#define TLS_VERSION_10 (uint8_t[2]){0x03, 0x01}
#define TLS_VERSION_11 (uint8_t[2]){0x03, 0x02}
#define TLS_VERSION_12 (uint8_t[2]){0x03, 0x03}




#include <stdint.h>

struct tls_record {
	uint8_t content_type;
	uint8_t tls_version[2];
	uint16_t length;
} __attribute__((__packed__));

#define TLS_HANDSHAKE_CLIENTHELLO 1
#define TLS_HANDSHAKE_SERVERHELLO 2


struct tls_handshake {
	uint8_t msg_type;
	uint8_t handshake_msg_len[3];
} __attribute__((__packed__));


struct random {
	uint32_t gmt_unix_time;
	uint8_t random_bytes[28];
} __attribute__((__packed__));

#define TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA {0x00, 0x13}
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA {0x00, 0x32}
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA {0x00, 0x33}
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 {0x00, 0x9e}
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA {0x00, 0x39}
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {0xcc, 0x15}
#define TLS_DH_ANON_WITH_RC4_128_MD5 {0x00, 0x18}
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA {0x00, 0x31}
#define TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA {0xc0, 0x08}
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA {0xc0, 0x09}
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 {0xc0, 0x23}
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {0xc0, 0x2b}
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA {0xc0, 0x0a}
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 {0xc0, 0x24}
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {0xc0, 0x2c}
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {0xcc, 0x14}
#define TLS_ECDHE_ECDSA_WITH_RC4_128_SHA {0xc0, 0x07}
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA {0xc0, 0x12}
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA {0xc0, 0x13}
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 {0xc0, 0x27}
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {0xc0, 0x2f}
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA {0xc0, 0x14}
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 {0xc0, 0x28}
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {0xc0, 0x30}
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {0xcc, 0x13}
#define TLS_ECDHE_RSA_WITH_RC4_128_SHA {0xc0, 0x11}
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV {0x00, 0xff}
#define TLS_GOSTR341001_WITH_28147_CNT_IMIT {0x00, 0x81}
#define TLS_RENEGO_PROTECTION_REQUEST {0x00, 0xff}
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA {0x00, 0x0a}
#define TLS_RSA_WITH_AES_128_CBC_SHA {0x00, 0x2f}
#define TLS_RSA_WITH_AES_128_CBC_SHA256 {0x00, 0x3c}
#define TLS_RSA_WITH_AES_128_GCM_SHA256 {0x00, 0x9c}
#define TLS_RSA_WITH_AES_256_CBC_SHA {0x00, 0x35}
#define TLS_RSA_WITH_AES_256_CBC_SHA256 {0x00, 0x3d}
#define TLS_RSA_WITH_AES_256_GCM_SHA384 {0x00, 0x9d}
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA {0x00, 0x41}
#define TLS_RSA_WITH_DES_CBC_SHA {0x00, 0x09}
#define TLS_RSA_WITH_RC4_128_MD5 {0x00, 0x04}
#define TLS_RSA_WITH_RC4_128_SHA {0x00, 0x05}



struct ciphersuits {
	uint8_t cipher_suits[2];
} __attribute__((__packed__));

extern struct ciphersuits tls_ciphers[40];



struct tls_ext {
	uint8_t type[2];
	uint16_t length; // big endian number of bytes that follow
} __attribute__((__packed__));


#define TLS_EXT_TYPE_STATUS (uint8_t[2]){0x00, 0x05}
#define TLS_STATUS_TYPE_OCSP 0x01

struct tls_ext_status_req {
	uint8_t cert_status_type;
	uint16_t responder_list_len; // 0
	uint16_t req_ext_len;  // 0
} __attribute__((__packed__));


#define TLS_EXT_TYPE_EC_POINT_FORMAT (uint8_t[2]){0x00, 0x0b}
#define TLS_EC_POINT_FORMAT_UNCOMPRESSED 0x00
#define TLS_EC_POINT_FORMAT_ASNI_COMPRESSED_PRIME 0x01
#define TLS_EC_POINT_FORMAT_ASNI_COMPRESSED_CHAR2 0x02

struct tls_ext_ec_point_format {
	uint8_t ec_point_format_len; // number of formats that follow
} __attribute__((__packed__));


struct curve {
	uint8_t curve[2];
} __attribute__((__packed__));


#define TLS_CURVE_SECP256R1 {0x00, 0x17}
#define TLS_CURVE_SECP384R1 {0x00, 0x18}
#define TLS_CURVE_SECP521R1 {0x00, 0x19}


extern struct curve tls_curves[3];


#define TLS_EXT_TYPE_EC_CURVES (uint8_t[2]){0x00, 0x0a}
struct tls_ext_ec_curves {
	uint16_t len_curves; // number of bytes used by cuves that follow
} __attribute__((__packed__));


struct sig_algo {
    uint8_t algo[2];
} __attribute__((packed));

#define SHA512_RSA {0x06,0x01}
#define SHA512_DSA {0x06,0x02}
#define SHA512_ECDSA {0x06,0x03}
#define SHA384_RSA {0x05,0x01}
#define SHA384_DSA {0x05,0x02}
#define SHA384_ECDSA {0x05,0x03}
#define SHA256_RSA {0x04,0x01}
#define SHA256_DSA {0x04,0x02}
#define SHA256_ECDSA {0x04,0x03}
#define SHA224_RSA {0x03,0x01}
#define SHA224_DSA {0x03,0x02}
#define SHA224_ECDSA {0x03,0x03}
#define SHA1_RSA {0x02,0x01}
#define SHA1_DSA {0x02,0x02}
#define SHA1_ECDSA {0x02,0x03}

extern struct sig_algo tls_sig_algos[15];

#define TLS_EXT_TYPE_SIG_ALGOS (uint8_t[2]){0x00, 0x0d}
struct tls_ext_sig_algos {
    uint16_t len_all;
    uint16_t len_algos;
} __attribute__((__packed__));

#define TLS_EXT_TYPE_SERVER_NAME (uint8_t[2]){0x00, 0x00}
struct tls_ext_sni {
    uint16_t ext_size;
    uint8_t name_type;
    uint16_t name_length;
} __attribute__((__packed__));

struct tls_client_hello {
	uint8_t tls_version[2];
	struct random random;
	uint8_t session_id_length; // put 0 here
	uint16_t cipher_suit_length; // use 30 bytes
	struct ciphersuits ciphers[sizeof(tls_ciphers)/sizeof(tls_ciphers[0])];
	uint8_t compression_method_length;
	uint8_t compression_method; // use NULL
	uint16_t extension_length; // use 0 byste
} __attribute__((__packed__));


struct tls_server_hello {
    uint8_t tls_version[2];
    struct random random;
    uint8_t session_id_length; // put 0 here
    uint8_t session_id[32];
    struct ciphersuits ciphers[1];
    uint8_t compression_method; // use NULL
    uint16_t extension_length; // use 0 byste
} __attribute__((__packed__));

#define TLS_EXT_TYPE_ALPN (uint8_t[2]){0x00, 0x10}
struct tls_ext_alpn {
    uint16_t len_prots; // number of bytes used by cuves that follow
} __attribute__((__packed__));



#define TLS_EXT_TYPE_NPN (uint8_t[2]){0x33, 0x74}
struct tls_ext_npn {
    uint8_t len; // number of bytes used by the protocol
} __attribute__((__packed__));


#endif
