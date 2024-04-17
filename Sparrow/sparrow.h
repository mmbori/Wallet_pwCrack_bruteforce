#pragma once

#include <sqlext.h>
#include <stdio.h>
#include <windows.h>
#include <sql.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <argon2.h>
#include <ctype.h>

void get_salt(uint8_t* sparrow_salt, const char* db_name);
int key_derivation(const uint8_t* password, const uint8_t* salt, char* pubKeyComp, EC_GROUP* curve, BIGNUM* privKey, BIGNUM* x, BIGNUM* y);

// DB header
void print_error(SQLHANDLE handle, SQLSMALLINT type);
int initialize_environment(SQLHANDLE* env);
void free_connection(SQLHANDLE con);
int test_connection(SQLHANDLE env, const char* db_name, const char* pwd, SQLHANDLE* con);
void start_server(char* db_name);