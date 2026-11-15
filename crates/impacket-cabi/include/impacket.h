/**
 * \file impacket.h
 * \brief C-compatible ABI and FFI bindings for impacket-rs.
 *
 * Provides C/C++ implants, BOFs, and foreign languages access to pure-Rust
 * Impacket protocols, target parsing, cryptographic primitives, and credential decoders.
 */

#ifndef IMPACKET_H
#define IMPACKET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status and Error Codes */
#define IMPACKET_OK                     0
#define IMPACKET_ERR_INVALID_PARAM     -1
#define IMPACKET_ERR_BUFFER_TOO_SMALL  -2
#define IMPACKET_ERR_PARSE_FAILED      -3
#define IMPACKET_ERR_CRYPTO_FAILED     -4

/**
 * \struct impacket_target_t
 * \brief Parsed target connection and credential parameters.
 */
typedef struct {
    char domain[256];
    char username[256];
    char password[256];
    char target_host[256];
    char target_ip[64];
    uint16_t port;
} impacket_target_t;

/**
 * \brief Returns the null-terminated version string of impacket-rs (e.g. "0.3.0").
 */
const char* impacket_version(void);

/**
 * \brief Parses a standard target specifier (e.g. "DOMAIN/user:pass@192.168.1.10:445").
 * \param spec Null-terminated target specification string.
 * \param out_target Pointer to target structure to populate.
 * \return IMPACKET_OK on success, or negative error code.
 */
int32_t impacket_parse_target(const char* spec, impacket_target_t* out_target);

/**
 * \brief Computes the 16-byte NT hash of a UTF-8 or ASCII password.
 * \param password Null-terminated password string.
 * \param out_hash 16-byte buffer to receive MD4(UTF-16LE(password)).
 * \return IMPACKET_OK on success, or negative error code.
 */
int32_t impacket_ntlm_hash(const char* password, uint8_t out_hash[16]);

/**
 * \brief Computes the legacy 16-byte LAN Manager (LM) hash.
 * \param password Null-terminated password string.
 * \param out_hash 16-byte buffer to receive LM hash.
 * \return IMPACKET_OK on success, or negative error code.
 */
int32_t impacket_lm_hash(const char* password, uint8_t out_hash[16]);

/**
 * \brief Computes the 16-byte NTLMv2 response hash (NTOWFv2).
 * \param ntlm_hash 16-byte NT hash.
 * \param username Null-terminated username.
 * \param domain Null-terminated target domain.
 * \param out_ntowf 16-byte buffer to receive HMAC-MD5(NT-Hash, UPPER(user) || domain).
 * \return IMPACKET_OK on success, or negative error code.
 */
int32_t impacket_ntlmv2_ntowf(
    const uint8_t ntlm_hash[16],
    const char* username,
    const char* domain,
    uint8_t out_ntowf[16]
);

/**
 * \brief Computes MD4 digest.
 */
int32_t impacket_md4(const uint8_t* data, size_t len, uint8_t out_digest[16]);

/**
 * \brief Computes MD5 digest.
 */
int32_t impacket_md5(const uint8_t* data, size_t len, uint8_t out_digest[16]);

/**
 * \brief Computes SHA-1 digest.
 */
int32_t impacket_sha1(const uint8_t* data, size_t len, uint8_t out_digest[20]);

/**
 * \brief Computes SHA-256 digest.
 */
int32_t impacket_sha256(const uint8_t* data, size_t len, uint8_t out_digest[32]);

/**
 * \brief Applies RC4 stream cipher in-place.
 */
int32_t impacket_rc4(const uint8_t* key, size_t key_len, uint8_t* data, size_t data_len);

/**
 * \brief Encrypts single 8-byte block using DES-ECB with 7-byte raw key.
 */
int32_t impacket_des_encrypt_block(
    const uint8_t key_7[7],
    const uint8_t in_block[8],
    uint8_t out_block[8]
);

/**
 * \brief Decrypts Group Policy Preferences (GPP) cpassword string.
 * \param cpassword Base64-encoded encrypted cpassword string.
 * \param out_buf Buffer to receive null-terminated plaintext password.
 * \param out_buf_len Size of out_buf in bytes.
 * \return IMPACKET_OK on success, or negative error code.
 */
int32_t impacket_decrypt_cpassword(const char* cpassword, char* out_buf, size_t out_buf_len);

/**
 * \brief Formats a binary binary SID structure into string form ("S-1-5-...").
 * \param sid_bytes Raw byte slice containing binary SID.
 * \param sid_len Length of raw byte slice.
 * \param out_str Buffer to receive null-terminated SID string.
 * \param out_str_len Size of out_str in bytes.
 * \return IMPACKET_OK on success, or negative error code.
 */
int32_t impacket_sid_to_string(
    const uint8_t* sid_bytes,
    size_t sid_len,
    char* out_str,
    size_t out_str_len
);

/**
 * \brief Parses a Kerberos AS-REP DER message and formats a Hashcat roasted hash ($krb5asrep$...).
 * \param asrep_der Pointer to raw ASN.1 DER encoded AS-REP.
 * \param asrep_len Length of DER bytes.
 * \param username Null-terminated Kerberos principal name.
 * \param realm Null-terminated Kerberos realm name.
 * \param out_buf Buffer to receive null-terminated Hashcat hash.
 * \param out_buf_len Size of out_buf in bytes.
 * \return IMPACKET_OK on success, or negative error code.
 */
int32_t impacket_krb5_parse_asrep_hashcat(
    const uint8_t* asrep_der,
    size_t asrep_len,
    const char* username,
    const char* realm,
    char* out_buf,
    size_t out_buf_len
);

/**
 * \brief Frees dynamically allocated string allocated by impacket C ABI.
 */
void impacket_free_string(char* str);

#ifdef __cplusplus
}
#endif

#endif /* IMPACKET_H */
