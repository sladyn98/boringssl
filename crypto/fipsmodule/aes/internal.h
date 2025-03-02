/* Copyright (c) 2017, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_AES_INTERNAL_H
#define OPENSSL_HEADER_AES_INTERNAL_H

#include <stdlib.h>

#include <openssl/cpu.h>

#if defined(__cplusplus)
extern "C" {
#endif


#if !defined(OPENSSL_NO_ASM)

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
#define HWAES
#define HWAES_ECB

OPENSSL_INLINE int hwaes_capable(void) {
  return (OPENSSL_ia32cap_get()[1] & (1 << (57 - 32))) != 0;
}

#define VPAES
#if defined(OPENSSL_X86_64)
#define VPAES_CTR32
#endif
OPENSSL_INLINE int vpaes_capable(void) {
  return (OPENSSL_ia32cap_get()[1] & (1 << (41 - 32))) != 0;
}

#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
#define HWAES

OPENSSL_INLINE int hwaes_capable(void) { return CRYPTO_is_ARMv8_AES_capable(); }

#if defined(OPENSSL_ARM)
#define BSAES
OPENSSL_INLINE int bsaes_capable(void) { return CRYPTO_is_NEON_capable(); }
#endif

#if defined(OPENSSL_AARCH64)
#define VPAES
#define VPAES_CTR32
OPENSSL_INLINE int vpaes_capable(void) { return CRYPTO_is_NEON_capable(); }
#endif

#elif defined(OPENSSL_PPC64LE)
#define HWAES

OPENSSL_INLINE int hwaes_capable(void) {
  return CRYPTO_is_PPC64LE_vcrypto_capable();
}
#elif defined(OPENSSL_S390X)
#define HWAES
#define HWAES_CTR

OPENSSL_INLINE int hwaes_capable(void) {
  return CRYPTO_is_s390x_capable();
}

OPENSSL_INLINE int hwaes_ctr_capable(void) {
  return CRYPTO_is_s390x_capable();
}
#endif

#endif  // !NO_ASM


#if defined(HWAES)

int aes_hw_set_encrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
int aes_hw_set_decrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
void aes_hw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_hw_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_hw_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                        const AES_KEY *key, uint8_t *ivec, const int enc);
void aes_hw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                 const AES_KEY *key, const uint8_t ivec[16]);

# if defined(HWAES_CTR)

void aes_hw_ctr128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
			   const AES_KEY *key, uint8_t ivec[AES_BLOCK_SIZE],
			   uint8_t ecount_buf[AES_BLOCK_SIZE], unsigned int *num);

# else

OPENSSL_INLINE int hwaes_ctr_capable(void) { return 0; }

void aes_hw_ctr128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                          const AES_KEY *key, uint8_t ivec[AES_BLOCK_SIZE],
                          uint8_t ecount_buf[AES_BLOCK_SIZE], unsigned int *num) {
  abort();
}

# endif

#else

// If HWAES isn't defined then we provide dummy functions for each of the hwaes
// functions.
OPENSSL_INLINE int hwaes_capable(void) { return 0; }

OPENSSL_INLINE int aes_hw_set_encrypt_key(const uint8_t *user_key, int bits,
                                          AES_KEY *key) {
  abort();
}

OPENSSL_INLINE int aes_hw_set_decrypt_key(const uint8_t *user_key, int bits,
                                          AES_KEY *key) {
  abort();
}

OPENSSL_INLINE void aes_hw_encrypt(const uint8_t *in, uint8_t *out,
                                   const AES_KEY *key) {
  abort();
}

OPENSSL_INLINE void aes_hw_decrypt(const uint8_t *in, uint8_t *out,
                                   const AES_KEY *key) {
  abort();
}

OPENSSL_INLINE void aes_hw_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                       size_t length, const AES_KEY *key,
                                       uint8_t *ivec, int enc) {
  abort();
}

OPENSSL_INLINE void aes_hw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                                size_t len, const AES_KEY *key,
                                                const uint8_t ivec[16]) {
  abort();
}

#endif  // !HWAES


#if defined(HWAES_ECB)
void aes_hw_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                        const AES_KEY *key, const int enc);
#endif  // HWAES_ECB


#if defined(BSAES)
// On platforms where BSAES gets defined (just above), then these functions are
// provided by asm. Note |bsaes_cbc_encrypt| requires |enc| to be zero.
void bsaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t ivec[16], int enc);
void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]);
#else
OPENSSL_INLINE char bsaes_capable(void) { return 0; }

// On other platforms, bsaes_capable() will always return false and so the
// following will never be called.
OPENSSL_INLINE void bsaes_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                      size_t length, const AES_KEY *key,
                                      uint8_t ivec[16], int enc) {
  abort();
}

OPENSSL_INLINE void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                               size_t len, const AES_KEY *key,
                                               const uint8_t ivec[16]) {
  abort();
}
#endif  // !BSAES


#if defined(VPAES)
// On platforms where VPAES gets defined (just above), then these functions are
// provided by asm.
int vpaes_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
int vpaes_set_decrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);

void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void vpaes_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

void vpaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t *ivec, int enc);
#if defined(VPAES_CTR32)
void vpaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]);
#endif
#else
OPENSSL_INLINE char vpaes_capable(void) { return 0; }

// On other platforms, vpaes_capable() will always return false and so the
// following will never be called.
OPENSSL_INLINE int vpaes_set_encrypt_key(const uint8_t *userKey, int bits,
                                         AES_KEY *key) {
  abort();
}
OPENSSL_INLINE int vpaes_set_decrypt_key(const uint8_t *userKey, int bits,
                                         AES_KEY *key) {
  abort();
}
OPENSSL_INLINE void vpaes_encrypt(const uint8_t *in, uint8_t *out,
                                  const AES_KEY *key) {
  abort();
}
OPENSSL_INLINE void vpaes_decrypt(const uint8_t *in, uint8_t *out,
                                  const AES_KEY *key) {
  abort();
}
OPENSSL_INLINE void vpaes_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                      size_t length, const AES_KEY *key,
                                      uint8_t *ivec, int enc) {
  abort();
}
#endif  // !VPAES


void aes_nohw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_nohw_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
int aes_nohw_set_encrypt_key(const uint8_t *key, unsigned bits,
                             AES_KEY *aeskey);
int aes_nohw_set_decrypt_key(const uint8_t *key, unsigned bits,
                             AES_KEY *aeskey);

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))
#define AES_NOHW_CBC
void aes_nohw_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                          const AES_KEY *key, uint8_t *ivec, const int enc);
#endif


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_AES_INTERNAL_H
