#include "sparrow.h"

// DB ====================================================

//for debugging. print error
void print_error(SQLHANDLE handle, SQLSMALLINT type) {
    SQLWCHAR sqlstate[6];
    SQLWCHAR message[512];
    SQLINTEGER native_error;
    SQLSMALLINT length;

    int recNum = 1;

    while (SQLGetDiagRec(type, handle, recNum, sqlstate, &native_error, message, sizeof(message) / sizeof(SQLWCHAR), &length) != SQL_NO_DATA) {
        printf("error %d:\n", recNum);
        printf(" SQLState: %ls\n", sqlstate);
        printf(" NativeError: %d\n", native_error);
        printf(" Message: %ls\n", message);
        recNum++;
    }
}

//initialize environment
int initialize_environment(SQLHANDLE* env) {

    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, env)) return -1;

    if (SQL_SUCCESS != SQLSetEnvAttr(*env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0)) return -1;
    return 0;
}

//free connection
void free_connection(SQLHANDLE con) {
    SQLFreeHandle(SQL_HANDLE_DBC, con);
}

//try connect to db
int test_connection(SQLHANDLE env, const char* db_name, const char* pwd, SQLHANDLE* con) {
    SQLWCHAR connectionString[1024];

    swprintf(connectionString, 1024, L"DRIVER={PostgreSQL Unicode(x64)};SERVER=localhost;PORT=5435;DATABASE=%hs;UID=sa;PWD=%hs;", db_name, pwd);

    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_DBC, env, con)) return -1;

    SQLRETURN ret = SQLDriverConnect(*con, NULL, connectionString, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
        free_connection(con);
        return 1;
    }
    else {
        return 0;
    }
}

//start h2db server
void start_server(char* db_name) {
    char cmd[512];
    sprintf_s(cmd, sizeof(cmd), "start \"\" server.bat %s", db_name);
    system(cmd);
}


// sparrow ===========================================

void get_salt(uint8_t* sparrow_salt, const char* db_name) {

    char file_name[256];
    snprintf(file_name, sizeof(file_name), "%s.mv.db", db_name);

    FILE* db;
    errno_t err = fopen_s(&db, file_name, "rb");

    if (err != 0 || !db) {
        perror("Failed to open file");
        return;
    }

    fseek(db, 24, SEEK_SET);
    fread(sparrow_salt, 1, 16, db);
    fclose(db);
}

int key_derivation(const uint8_t* password, const uint8_t* salt, char* pubKeyComp, EC_GROUP* curve, BIGNUM* privKey, BIGNUM* x, BIGNUM* y) {

    uint8_t derivedKey[32];
    uint32_t time_cost = 10;
    uint32_t memory_cost = 256 * 1024;
    uint32_t parallelism = 4;
    uint32_t hash_length = 32;

    //Create derivedKey
    int result = argon2id_hash_raw(time_cost, memory_cost, parallelism, password, strlen((char*)password), salt, 16, derivedKey, hash_length);
    if (result != ARGON2_OK) {
        fprintf(stderr, "Error: %s\n", argon2_error_message(result));
        return -1;
    }

    //Convert derivedKey to BIGNUM
    BN_bin2bn(derivedKey, sizeof(derivedKey), privKey);

    //Create pubKey
    EC_POINT* pubKey = EC_POINT_new(curve);
    EC_POINT_mul(curve, pubKey, privKey, NULL, NULL, NULL);


    //Get affine coordinates (x, y) of pubKey
    if (!EC_POINT_get_affine_coordinates(curve, pubKey, x, y, NULL)) {
        fprintf(stderr, "Failed to get affine coordinates.\n");
        return -1;
    }

    //Compress pubKey
    int parity = BN_is_odd(y);
    char* x_hex = BN_bn2hex(x);
    snprintf(pubKeyComp, 67, "0%d%s", 2 + parity, x_hex);

    for (int i = 0; pubKeyComp[i]; i++) {
        pubKeyComp[i] = tolower(pubKeyComp[i]);
    }

    //Clean
    EC_POINT_free(pubKey);
    OPENSSL_free(x_hex);

    return 0;
}


int main() {

    SQLHANDLE env;
    SQLHANDLE con;
    initialize_environment(&env);

    char db_name[] = "test";
    start_server(db_name);

    //salt parsing
    uint8_t sparrow_salt[16];
    get_salt(sparrow_salt, db_name);

    //password guessing
    uint8_t* password[] = { "1112", "1112", "1112", "1112", "1112", "1112", "1112", "1112", "1112", "1111" };
    int passwordCount = sizeof(password) / sizeof(password[0]);

    //precompute EC_GROUP
    EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!curve) {
        fprintf(stderr, "Failed to create curve\n");
        return -1;
    }
    BIGNUM* privKey = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    clock_t start = clock();

    for (int i = 0; i < passwordCount; i++) {
        clock_t try_t = clock();

        //Key derivation
        char pubKeyComp[68];
        key_derivation(password[i], sparrow_salt, pubKeyComp, curve, privKey, x, y);
        strcat_s(pubKeyComp, sizeof(pubKeyComp), " ");

        //Crack DB
        clock_t try_connect = clock();
        if (test_connection(env, db_name, pubKeyComp, &con)) {
            clock_t end = clock();
            printf("[%d] try [%s] success : %.3f \n", i + 1, password[i], (double)(end - try_t) / CLOCKS_PER_SEC);
            printf("Total Time : %.3f \n", (double)(end - start) / CLOCKS_PER_SEC);
            break;
        }
        else {
            clock_t end = clock();
            printf("[%d] try [%s] fail : %.3f \n", i + 1, password[i], (double)(end - try_t) / CLOCKS_PER_SEC);
            printf("[%d] db connect time : %.3f \n", i + 1, (double)(end - try_connect) / CLOCKS_PER_SEC);
            if (i + 1 % 100 == 0) {
                printf("Total Time : %.3f \n", (double)(end - start) / CLOCKS_PER_SEC);
            }
        }
    }

    BN_free(privKey);
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(curve);

    printf("Press Enter to continue...\n");
    (void)getchar();

    return 0;
}