// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose.h
 * @brief Core COSE types, status codes, and IANA constants (RFC 9052/9053).
 *
 * This is the base C header for the COSE SDK. It defines types and constants
 * that are shared across all COSE operations — signing, validation, crypto,
 * and extension packs.
 *
 * Higher-level headers (e.g., `<cose/sign1.h>`) include this automatically.
 *
 * ## Status Codes
 *
 * Functions in the validation / extension-pack layer return `cose_status_t`.
 * Functions in the primitives / signing layer return `int32_t` with
 * `COSE_SIGN1_*` codes (defined in `<cose/sign1.h>`).
 *
 * ## Memory Management
 *
 * - Opaque handles must be freed with the matching `*_free()` function.
 * - Strings returned by the library must be freed with `cose_string_free()`.
 * - Byte buffers document their ownership per-function.
 */

#ifndef COSE_COSE_H
#define COSE_COSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* Status type (validation / extension-pack layer)                            */
/* ========================================================================== */

#ifndef COSE_STATUS_T_DEFINED
#define COSE_STATUS_T_DEFINED

/**
 * @brief Status codes returned by validation and extension-pack functions.
 */
typedef enum cose_status_t {
    COSE_OK          = 0,
    COSE_ERR         = 1,
    COSE_PANIC       = 2,
    COSE_INVALID_ARG = 3
} cose_status_t;

#endif /* COSE_STATUS_T_DEFINED */

/* ========================================================================== */
/* Thread-local error reporting utilities                                     */
/* ========================================================================== */

/**
 * @brief Retrieve the last error message (UTF-8, null-terminated).
 *
 * The caller owns the returned string and must free it with
 * `cose_string_free()`. Returns NULL if no error is set.
 */
char* cose_last_error_message_utf8(void);

/**
 * @brief Clear the thread-local error state.
 */
void cose_last_error_clear(void);

/**
 * @brief Free a string returned by this library.
 * @param s  String to free (NULL is a safe no-op).
 */
void cose_string_free(char* s);

/* ========================================================================== */
/* Opaque handle types – generic COSE                                         */
/* ========================================================================== */

/**
 * @brief Opaque handle to a COSE header map.
 *
 * A header map represents the protected or unprotected headers of a COSE
 * structure. Use `cose_headermap_*` functions to inspect or build header maps.
 * Free with `cose_headermap_free()`.
 */
typedef struct CoseHeaderMapHandle CoseHeaderMapHandle;

/**
 * @brief Opaque handle to a COSE key.
 *
 * Represents a public or private key used for signing/verification.
 * Free with `cose_key_free()`.
 */
typedef struct CoseKeyHandle CoseKeyHandle;

/* ========================================================================== */
/* Header map – read operations                                               */
/* ========================================================================== */

/**
 * @brief Free a header map handle.
 * @param headers  Handle to free (NULL is a safe no-op).
 */
void cose_headermap_free(CoseHeaderMapHandle* headers);

/**
 * @brief Look up an integer header value by integer label.
 *
 * @param headers   Header map.
 * @param label     Integer label (e.g., `COSE_HEADER_ALG`).
 * @param out_value Receives the integer value on success.
 * @return 0 on success, negative error code on failure.
 */
int32_t cose_headermap_get_int(
    const CoseHeaderMapHandle* headers,
    int64_t label,
    int64_t* out_value
);

/**
 * @brief Look up a byte-string header value by integer label.
 *
 * The returned pointer is borrowed from the header map and is valid only
 * as long as the header map handle is alive.
 *
 * @param headers   Header map.
 * @param label     Integer label.
 * @param out_bytes Receives a pointer to the byte data.
 * @param out_len   Receives the byte length.
 * @return 0 on success, negative error code on failure.
 */
int32_t cose_headermap_get_bytes(
    const CoseHeaderMapHandle* headers,
    int64_t label,
    const uint8_t** out_bytes,
    size_t* out_len
);

/**
 * @brief Look up a text-string header value by integer label.
 *
 * Returns a newly-allocated UTF-8 string. Caller must free with
 * `cose_sign1_string_free()` (primitives layer) or `cose_string_free()`.
 *
 * @param headers  Header map.
 * @param label    Integer label.
 * @return Allocated string, or NULL if not found.
 */
char* cose_headermap_get_text(
    const CoseHeaderMapHandle* headers,
    int64_t label
);

/**
 * @brief Check whether a header with the given integer label exists.
 */
bool cose_headermap_contains(
    const CoseHeaderMapHandle* headers,
    int64_t label
);

/**
 * @brief Return the number of entries in the header map.
 */
size_t cose_headermap_len(const CoseHeaderMapHandle* headers);

/* ========================================================================== */
/* Key operations                                                             */
/* ========================================================================== */

/**
 * @brief Free a key handle.
 * @param key  Handle to free (NULL is a safe no-op).
 */
void cose_key_free(CoseKeyHandle* key);

/**
 * @brief Get the COSE algorithm identifier for a key.
 *
 * @param key     Key handle.
 * @param out_alg Receives the algorithm (e.g., `COSE_ALG_ES256`).
 * @return 0 on success, negative error code on failure.
 */
int32_t cose_key_algorithm(
    const CoseKeyHandle* key,
    int64_t* out_alg
);

/**
 * @brief Get a human-readable key-type string.
 *
 * The caller must free the returned string with the appropriate
 * `*_string_free()` function.
 *
 * @param key  Key handle.
 * @return Allocated string, or NULL on failure.
 */
char* cose_key_type(const CoseKeyHandle* key);

/* ========================================================================== */
/* IANA COSE Constants – Header Labels (RFC 9052 §3.1)                        */
/* ========================================================================== */

/** @brief Algorithm identifier header label. */
#define COSE_HEADER_ALG             1
/** @brief Critical headers label. */
#define COSE_HEADER_CRIT            2
/** @brief Content type header label. */
#define COSE_HEADER_CONTENT_TYPE    3
/** @brief Key ID header label. */
#define COSE_HEADER_KID             4
/** @brief Initialization Vector header label. */
#define COSE_HEADER_IV              5
/** @brief Partial IV header label. */
#define COSE_HEADER_PARTIAL_IV      6

/* X.509 certificate headers */
/** @brief X.509 certificate bag (unordered). */
#define COSE_HEADER_X5BAG           32
/** @brief X.509 certificate chain (ordered). */
#define COSE_HEADER_X5CHAIN         33
/** @brief X.509 certificate thumbprint (SHA-256). */
#define COSE_HEADER_X5T             34
/** @brief X.509 certificate URI. */
#define COSE_HEADER_X5U             35

/* ========================================================================== */
/* IANA COSE Constants – Algorithm IDs (RFC 9053)                             */
/* ========================================================================== */

/** @brief ECDSA w/ SHA-256 (P-256). */
#define COSE_ALG_ES256              (-7)
/** @brief ECDSA w/ SHA-384 (P-384). */
#define COSE_ALG_ES384              (-35)
/** @brief ECDSA w/ SHA-512 (P-521). */
#define COSE_ALG_ES512              (-36)
/** @brief EdDSA (Ed25519 / Ed448). */
#define COSE_ALG_EDDSA              (-8)
/** @brief RSASSA-PSS w/ SHA-256. */
#define COSE_ALG_PS256              (-37)
/** @brief RSASSA-PSS w/ SHA-384. */
#define COSE_ALG_PS384              (-38)
/** @brief RSASSA-PSS w/ SHA-512. */
#define COSE_ALG_PS512              (-39)
/** @brief RSASSA-PKCS1-v1_5 w/ SHA-256. */
#define COSE_ALG_RS256              (-257)
/** @brief RSASSA-PKCS1-v1_5 w/ SHA-384. */
#define COSE_ALG_RS384              (-258)
/** @brief RSASSA-PKCS1-v1_5 w/ SHA-512. */
#define COSE_ALG_RS512              (-259)

#ifdef COSE_ENABLE_PQC
/** @brief ML-DSA-44 (FIPS 204, category 2). */
#define COSE_ALG_ML_DSA_44          (-48)
/** @brief ML-DSA-65 (FIPS 204, category 3). */
#define COSE_ALG_ML_DSA_65          (-49)
/** @brief ML-DSA-87 (FIPS 204, category 5). */
#define COSE_ALG_ML_DSA_87          (-50)
#endif /* COSE_ENABLE_PQC */

/* ========================================================================== */
/* IANA COSE Constants – Key Types (RFC 9053)                                 */
/* ========================================================================== */

/** @brief Octet Key Pair (EdDSA, X25519, X448). */
#define COSE_KTY_OKP                1
/** @brief Elliptic Curve (ECDSA P-256/384/521). */
#define COSE_KTY_EC2                2
/** @brief RSA (RSASSA-PKCS1, RSASSA-PSS). */
#define COSE_KTY_RSA                3
/** @brief Symmetric (AES, HMAC). */
#define COSE_KTY_SYMMETRIC          4

/* ========================================================================== */
/* IANA COSE Constants – EC Curves (RFC 9053)                                 */
/* ========================================================================== */

/** @brief P-256 (secp256r1). */
#define COSE_CRV_P256               1
/** @brief P-384 (secp384r1). */
#define COSE_CRV_P384               2
/** @brief P-521 (secp521r1). */
#define COSE_CRV_P521               3
/** @brief X25519 (key agreement). */
#define COSE_CRV_X25519             4
/** @brief X448 (key agreement). */
#define COSE_CRV_X448               5
/** @brief Ed25519 (EdDSA signing). */
#define COSE_CRV_ED25519            6
/** @brief Ed448 (EdDSA signing). */
#define COSE_CRV_ED448              7

/* ========================================================================== */
/* IANA COSE Constants – Hash Algorithms                                      */
/* ========================================================================== */

/** @brief SHA-256. */
#define COSE_HASH_SHA256            (-16)
/** @brief SHA-384. */
#define COSE_HASH_SHA384            (-43)
/** @brief SHA-512. */
#define COSE_HASH_SHA512            (-44)

/* ========================================================================== */
/* CWT Claim Labels (RFC 8392)                                                */
/* ========================================================================== */

/** @brief Issuer (iss). */
#define COSE_CWT_CLAIM_ISS          1
/** @brief Subject (sub). */
#define COSE_CWT_CLAIM_SUB          2
/** @brief Confirmation (cnf). */
#define COSE_CWT_CLAIM_CNF          8

/* ========================================================================== */
/* Well-known Content Types                                                   */
/* ========================================================================== */

/** @brief SCITT indirect-signature statement. */
#define COSE_CONTENT_TYPE_SCITT_STATEMENT \
    "application/vnd.microsoft.scitt.statement+cose"

/** @brief COSE_Sign1 with embedded payload. */
#define COSE_CONTENT_TYPE_COSE_SIGN1 \
    "application/cose; cose-type=cose-sign1"

#ifdef __cplusplus
}
#endif

#endif /* COSE_COSE_H */
