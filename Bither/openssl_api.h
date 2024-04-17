#pragma once

#include "bither.h"

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>

#include <openssl/aes.h>


#define SCRYPT_N 16384
#define SCRYPT_R 8
#define SCRYPT_P 1

#define OSSL_KDF_PARAM_SECRET       "secret"    /* octet string */
#define OSSL_KDF_PARAM_KEY          "key"       /* octet string */
#define OSSL_KDF_PARAM_SALT         "salt"      /* octet string */
#define OSSL_KDF_PARAM_PASSWORD     "pass"      /* octet string */
#define OSSL_KDF_PARAM_SCRYPT_N     "n"         /* uint64_t */
#define OSSL_KDF_PARAM_SCRYPT_R     "r"         /* uint32_t */
#define OSSL_KDF_PARAM_SCRYPT_P     "p"         /* uint32_t */


//bither
int openssl_aes256(uint8_t* out, int outlen, uint8_t* in, int inlen, uint8_t* key, uint8_t* iv);
int openssl_scrypt(uint8_t* key, int key_len, uint8_t* salt, int salt_len, uint8_t* password, int password_len);
