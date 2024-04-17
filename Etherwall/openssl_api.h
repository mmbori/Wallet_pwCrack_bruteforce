#pragma once

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>

#include <openssl/aes.h>


#define OSSL_KDF_PARAM_SECRET       "secret"    /* octet string */
#define OSSL_KDF_PARAM_KEY          "key"       /* octet string */
#define OSSL_KDF_PARAM_SALT         "salt"      /* octet string */
#define OSSL_KDF_PARAM_PASSWORD     "pass"      /* octet string */
#define OSSL_KDF_PARAM_SCRYPT_N     "n"         /* uint64_t */
#define OSSL_KDF_PARAM_SCRYPT_R     "r"         /* uint32_t */
#define OSSL_KDF_PARAM_SCRYPT_P     "p"         /* uint32_t */