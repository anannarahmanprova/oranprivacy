#include "Enclave_t.h"
#include <string.h>

// Secure storage for the key inside the enclave
uint8_t stored[32];

void store_key(uint8_t* key, size_t len) {
    ocall_print("Hello");
    if (len > sizeof(stored)) {
        ocall_print("Key size is too large.");
        return;
    }

    // Securely store the key inside the enclave memory
    memcpy(stored, key, len);
    ocall_print("Key stored securely inside the enclave.");
}

