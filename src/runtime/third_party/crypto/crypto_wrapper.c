// crypto_wrapper.c — Thin C glue between Eiwa and OpenSSL (libcrypto).
//
// Eiwa `String` is a plain `char*` in the LLVM backend, so all functions
// take/return `const char*`/`char*` directly. Returned strings are allocated
// with GC_malloc (Boehm GC is linked into every Eiwa binary), so callers
// never free them.
//
// Compiled into the program via `@Source` in native.ei.

#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

extern void* GC_malloc(size_t);

static const char B64URL_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char* to_hex(const unsigned char* bytes, size_t len) {
    static const char HEX[] = "0123456789abcdef";
    char* out = (char*)GC_malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = HEX[bytes[i] & 0xF];
    }
    out[len * 2] = '\0';
    return out;
}

// Base64url-encode `len` bytes. padding != 0 keeps trailing '=' (and the
// alphabet is still URL-safe: '+'/'/' are always replaced).
static char* b64url_encode(const unsigned char* data, size_t len, int padding) {
    size_t out_cap = ((len + 2) / 3) * 4 + 1;
    char* out = (char*)GC_malloc(out_cap);
    size_t o = 0;
    size_t i = 0;
    while (i + 3 <= len) {
        unsigned v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out[o++] = B64URL_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64URL_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = B64URL_ALPHABET[(v >> 6) & 0x3F];
        out[o++] = B64URL_ALPHABET[v & 0x3F];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        unsigned v = data[i] << 16;
        out[o++] = B64URL_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64URL_ALPHABET[(v >> 12) & 0x3F];
        if (padding) { out[o++] = '='; out[o++] = '='; }
    } else if (rem == 2) {
        unsigned v = (data[i] << 16) | (data[i + 1] << 8);
        out[o++] = B64URL_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64URL_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = B64URL_ALPHABET[(v >> 6) & 0x3F];
        if (padding) out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

static int b64url_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

// Decode base64url (with or without padding). Returns a GC-allocated buffer
// and writes the decoded length to *out_len. Returns NULL on invalid input.
static unsigned char* b64url_decode(const char* in, size_t* out_len) {
    size_t len = strlen(in);
    unsigned char* out = (unsigned char*)GC_malloc(len * 3 / 4 + 4);
    size_t o = 0;
    int acc = 0;
    int nbits = 0;
    for (size_t i = 0; i < len; i++) {
        if (in[i] == '=') break;
        int v = b64url_value(in[i]);
        if (v < 0) return NULL;
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            out[o++] = (unsigned char)((acc >> nbits) & 0xFF);
        }
    }
    *out_len = o;
    return out;
}

// ---------------------------------------------------------------------------
// Public API (bound from Eiwa via @Alias)
// ---------------------------------------------------------------------------

char* eiwa_crypto_sha256_hex(const char* data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data, strlen(data), digest);
    return to_hex(digest, SHA256_DIGEST_LENGTH);
}

// SHA-256 of a UTF-8 string, base64url-encoded without padding.
// This is the PKCE S256 code_challenge form (RFC 7636).
char* eiwa_crypto_sha256_b64url(const char* data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data, strlen(data), digest);
    return b64url_encode(digest, SHA256_DIGEST_LENGTH, 0);
}

char* eiwa_crypto_hmac_sha256_hex(const char* data, const char* key) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), key, (int)strlen(key),
         (const unsigned char*)data, strlen(data), mac, &mac_len);
    return to_hex(mac, mac_len);
}

char* eiwa_crypto_b64url_encode(const char* data, int64_t padding) {
    return b64url_encode((const unsigned char*)data, strlen(data), padding != 0);
}

// Encodes exactly `len` raw bytes read from `data` (binary-safe; used for
// random bytes that are NOT null-terminated strings).
char* eiwa_crypto_b64url_encode_bytes(const char* data, int64_t len, int64_t padding) {
    return b64url_encode((const unsigned char*)data, (size_t)len, padding != 0);
}

char* eiwa_crypto_b64url_decode(const char* data) {
    size_t out_len = 0;
    unsigned char* out = b64url_decode(data, &out_len);
    if (out == NULL) return NULL;
    out[out_len] = '\0';
    return (char*)out;
}

// Fills `buf` (GC-managed ByteArray-compatible raw bytes) with n
// cryptographically secure random bytes. Returns 1 on success, 0 on failure.
int64_t eiwa_crypto_random_bytes(char* buf, int64_t n) {
    return RAND_bytes((unsigned char*)buf, (int)n) == 1 ? 1 : 0;
}

// Generates `n` random bytes and returns them base64url-encoded without
// padding, truncated to `n` chars (mirrors generateSecureRandom in Kotlin:
// base64url of n random bytes, take(n)).
char* eiwa_crypto_random_base64url(int64_t n) {
    unsigned char* buf = (unsigned char*)GC_malloc((size_t)n);
    if (RAND_bytes(buf, (int)n) != 1) return NULL;
    char* enc = b64url_encode(buf, (size_t)n, 0);
    if ((int64_t)strlen(enc) > n) enc[n] = '\0';
    return enc;
}

// Signs `data` with an EC P-256 private key (PEM or DER-less PKCS#8 PEM) and
// returns the signature as base64url-no-padding of the raw r||s (64 bytes),
// which is the JWS/ES256 (RFC 7515) representation — not the ASN.1/DER form.
char* eiwa_crypto_sign_es256(const char* data, const char* private_key_pem) {
    BIO* bio = BIO_new_mem_buf(private_key_pem, -1);
    if (bio == NULL) return NULL;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (pkey == NULL) return NULL;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) { EVP_PKEY_free(pkey); return NULL; }

    unsigned char der[128];
    unsigned int der_len = 0;
    char* result = NULL;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestSignUpdate(ctx, data, strlen(data)) == 1) {
        size_t slen = sizeof(der);
        if (EVP_DigestSignFinal(ctx, der, &slen) == 1) {
            der_len = (unsigned int)slen;
            // Convert DER ECDSA-Sig-Value -> raw r||s (32 + 32 bytes)
            const unsigned char* p = der;
            ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &p, der_len);
            if (sig != NULL) {
                const BIGNUM* r;
                const BIGNUM* s;
                ECDSA_SIG_get0(sig, &r, &s);
                unsigned char raw[64];
                BN_bn2binpad(r, raw, 32);
                BN_bn2binpad(s, raw + 32, 32);
                result = b64url_encode(raw, 64, 0);
                ECDSA_SIG_free(sig);
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}
