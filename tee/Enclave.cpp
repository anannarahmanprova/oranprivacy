/* Enclave.cpp */
#include "Enclave_t.h"  // Auto-generated header from Enclave.edl
#include <stdio.h>

void ecall_process_command(const char *command) {
    // Securely process the command.
    // In a real-world scenario, you might validate, decrypt, or perform other operations.
    char response[128];
    snprintf(response, sizeof(response), "Enclave processed command: %s", command);

    // Use an OCALL to send the response back to the untrusted side.
    ocall_send_response(response);
}
