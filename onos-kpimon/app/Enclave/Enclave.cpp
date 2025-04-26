#include "Enclave_t.h"
#include <string.h>
#include <stdio.h> 

#define DECRYPTED_BUFFER_SIZE 2048
#define NONCE_SIZE 12
#define TAG_SIZE 16


const sgx_aes_gcm_128bit_key_t gcm_key = {
    0xa9, 0xf4, 0xb6, 0xc7,
    0xd1, 0xe2, 0xf3, 0xa4,
    0xb5, 0xc6, 0xd7, 0xe8,
    0xf9, 0xa0, 0xb1, 0xc2
};

sgx_status_t process_kpi(uint8_t* encrypted_payload, uint32_t len) {
    if (!encrypted_payload || len < (NONCE_SIZE + TAG_SIZE))
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t* nonce = encrypted_payload;
    uint8_t* ciphertext = encrypted_payload + NONCE_SIZE;
    uint32_t ciphertext_len = len - NONCE_SIZE - TAG_SIZE;
    uint8_t* tag = encrypted_payload + len - TAG_SIZE;

    uint8_t decrypted[DECRYPTED_BUFFER_SIZE] = {0};


    sgx_status_t decrypt_status = sgx_rijndael128GCM_decrypt(
        &gcm_key, 
        ciphertext, ciphertext_len,
        decrypted,
        nonce, NONCE_SIZE,
        NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)tag
    );

    if (decrypt_status != SGX_SUCCESS) {
        return decrypt_status;
    }

    return SGX_SUCCESS;
}
