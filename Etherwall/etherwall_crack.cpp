#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "etherwall.h"

void str2bin(char* output, const int output_len, char* input)
{
    char tmp[4] = { 0, };
    tmp[0] = '0';
    tmp[1] = 'x';

    for (int i = 0; i < output_len; i++)
    {
        tmp[2] = input[i * 2];
        tmp[3] = input[i * 2 + 1];
        output[i] = strtol(tmp, NULL, 16);
    }
}

int etherwall_parsing(Etherwall_Info* acc, const char* path) {

    char buffer[65] = { 0, };

    FILE* file;
    errno_t err = fopen_s(&file, path, "r");
    if (err != 0 || !file) {
        printf("Error opening file.\n");
        return FAIL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* data = (char*)malloc(length + 1); // +1 for null-terminator
    if (!data) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return FAIL;
    }
    // +1 for null-terminator
    size_t bytesRead = fread(data, 1, length, file);
    if (bytesRead != length) {
        printf("Error reading file.\n");
        free(data);
        fclose(file);
        return FAIL;
    }

    fclose(file);
    data[length] = '\0';  // Null-terminate the read data

    struct json_object* json = json_tokener_parse(data);
    if (!json) {
        printf("Error parsing JSON.\n");
        free(data);
        return FAIL;
    }

    // JSON parsing using json-c
    struct json_object* crypto;
    json_object_object_get_ex(json, "crypto", &crypto);
    // parse ciphertext
    strcpy_s(buffer, CIPHER_LEN * 2 + 1, json_object_get_string(json_object_object_get(crypto, "ciphertext")));
    str2bin(acc->ciphertext, CIPHER_LEN, buffer);
    // parse iv
    strcpy_s(buffer, IV_LEN * 2 + 1, json_object_get_string(json_object_object_get(json_object_object_get(crypto, "cipherparams"), "iv")));
    str2bin(acc->iv, IV_LEN, buffer);
    // parse mac
    strcpy_s(acc->mac, MAC_LEN + 1, json_object_get_string(json_object_object_get(crypto, "mac")));
    strupr(acc->mac);
    // parse scypt parameter
    struct json_object* kdfparams = json_object_object_get(crypto, "kdfparams");
    acc->kdf_n = json_object_get_int(json_object_object_get(kdfparams, "n"));
    acc->kdf_p = json_object_get_int(json_object_object_get(kdfparams, "p"));
    acc->kdf_r = json_object_get_int(json_object_object_get(kdfparams, "r"));
    // parse salt
    strcpy_s(buffer, SALT_LEN * 2 + 1, json_object_get_string(json_object_object_get(kdfparams, "salt")));
    str2bin(acc->kdf_salt, SALT_LEN, buffer);

    json_object_put(json);  // Clean up
    free(data);

    return SUCCESS;
}

int etherwall_key_derivation(char* pwd, int pwd_len, uint8_t* aesKey, Etherwall_Info* etherwall)
{
    if (crypto_pwhash_scryptsalsa208sha256_ll((const uint8_t*)pwd, (size_t)pwd_len, (const uint8_t*)etherwall->kdf_salt, SALT_LEN, etherwall->kdf_n,
        etherwall->kdf_r, etherwall->kdf_p, aesKey, AESKEY_LEN) != 0) {
        printf("Scryt error\n");
        return FAIL;
    }
    return SUCCESS;
}

int etherwall_key_verification(uint8_t* aesKey, Etherwall_Info* etherwall)
{
    uint8_t verify_input[48] = { 0 }; // 16 bytes for derivedKey[16:32] and 32 bytes for ciphertext

    // Prepare data for MAC computation: derivedKey[16:32] + ciphertext
    memcpy(verify_input, aesKey + 16, 16);
    memcpy(verify_input + 16, etherwall->ciphertext, CIPHER_LEN);

    // keccak =============================================
    CryptoPP::Keccak_256 keccak;

    uint8_t digest[CryptoPP::Keccak_256::DIGESTSIZE];

    keccak.CalculateDigest(digest, verify_input, 48);

    std::string output;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    char c_output[65] = { 0, };

    strcpy(c_output, output.c_str());

    if (strncmp(c_output, etherwall->mac, MAC_LEN) == 0)
    {
        return SUCCESS;
    }

    return FAIL;
}

int main()
{
    double total_clock;
    int len;
    uint8_t aesKey[32] = { 0, };
    clock_t start, end;
    Etherwall_Info etherwall = { 0, };

    uint8_t file_name[100];
    printf("File path : ");
    scanf("%99s", file_name);

    char password[40];
    printf("\nPassword : ");
    scanf("%39s", password);

    int pwd_len;
    printf("\nPassword length :");
    scanf("%d", &pwd_len);
    printf("\n");


    FILE* file = fopen((const char*)file_name, "r");

    if (etherwall_parsing(&etherwall, (const char*)file_name) == FAIL)
    {
        printf("*** Data parsing error ***\n");
        return FAIL;
    }

    etherwall_key_derivation(password, pwd_len, aesKey, &etherwall);
    if (etherwall_key_verification(aesKey, &etherwall) == SUCCESS)
    {
        printf("\n*** Valid Password! ***\n\n");
        return SUCCESS;
    }
    
    printf("\n*** Invalid Password ***\n");

    return 0;
}
