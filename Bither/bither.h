#pragma once
#pragma warning(disable : 4996)
#define _CRT_NONSTDC_NO_DEPRECATE

#define _BITHER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <time.h>

#include <sqlite3.h>

#include "openssl_api.h"

#define BITHER_TOTAL_PARSING_LEN 147
#define BITHER_PRIVKEY_LEN 48
#define BITHER_IV_LEN 16
#define BITHER_SALT_LEN 8
#define BITHER_AESKEY_LEN 32

#define SUCCESS 1
#define FAIL 0

typedef struct BitherInfo
{
	uint8_t encPrivKey[48];
	uint8_t salt[9];
	uint8_t iv[16];

}BitherInfo;

// tmp
//bither_key_derivation();

void BITHERstr2bin(uint8_t* output, const int output_len, char* input, const int start, const int odd);
int exec_callback(char* original, int argc, char** argv, char** azcolname);
int bither_data_parsing(BitherInfo* bither, const char* file_name);
int bither_key_derivation(uint8_t* pwd, uint8_t pwd16_len, BitherInfo* bither);
int bither_key_verification(uint8_t* aesKey, BitherInfo* bither);
int bither_crack(uint8_t* file_name, uint8_t* pwd);
