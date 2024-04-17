#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <time.h>

#include <sodium.h>
#include <json-c/json.h>

#include <string>
#include <cryptopp/keccak.h>
#include <cryptopp/hex.h>

#include "openssl_api.h"


#define SUCCESS 0
#define FAIL 1

#define CIPHER_LEN 32
#define IV_LEN 16
#define MAC_LEN 64
#define SALT_LEN 32
#define AESKEY_LEN 32

#define TO_ORIGINAL 33
#define NUM_OF_ASCII 94

#define MAX_LINES 100
#define LINE_LENGTH 20

//using namespace std;

typedef struct Etherwall_Info {
    char ciphertext[CIPHER_LEN];
    char iv[IV_LEN];
    char mac[MAC_LEN + 1];
    uint64_t kdf_n;
    uint32_t kdf_p;
    uint32_t kdf_r;
    char kdf_salt[SALT_LEN];
} Etherwall_Info;

void str2bin(char* output, const int output_len, char* input);
int etherwall_parsing(Etherwall_Info* acc, const char* path);
int etherwall_key_derivation(char* pwd, int pwd_len, uint8_t* aesKey, Etherwall_Info* etherwall);
int etherwall_key_verification(uint8_t* aesKey, Etherwall_Info* etherwall);
int etherwall_test(char files[MAX_LINES][LINE_LENGTH], int count);


