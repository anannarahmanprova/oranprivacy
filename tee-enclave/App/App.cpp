/*#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"


sgx_enclave_id_t global_eid = 0;


void ocall_print(const char* str) {
    printf("%s\n", str);
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    int ptr;
    sgx_status_t status = generate_random_number(global_eid, &ptr);
    std::cout << status << std::endl;
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    printf("Random number: %d\n", ptr);

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
        return 1;
    }

    int unsealed;
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (uint8_t*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back " << unsealed << std::endl;

    return 0;
}*/
#include <stdio.h>
#include <iostream>
#include <string.h>  // For memset()
#include <unistd.h>  // For close()
#include <sys/types.h>
#include <sys/socket.h>  // For socket(), connect()
#include <arpa/inet.h>   // For htons(), inet_pton()
#include <netinet/in.h>  // For sockaddr_in
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "sgx_urts.h"       // For SGX functions (initialize, destroy enclave)
#include "Enclave_u.h"      // For ECALLs (generated from EDL)
#include "sgx_error.h"      // For SGX error codes
#include "sgx_utils/sgx_utils.h"
#include <chrono>
#include <thread>


sgx_enclave_id_t global_eid = 0;

// Initialize OpenSSL
void initialize_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Create an SSL context
SSL_CTX* create_ssl_context() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context" << std::endl;
        return nullptr;
    }

    return ctx;
}

// Connect to RAN simulator and receive the key
void receive_key_over_tls(const char* server_ip, int port) {
    SSL_CTX* ctx = create_ssl_context();
    if (!ctx) return;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

     while (true) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            std::cout << "Connected to server!" << std::endl;
            break; // Exit loop once connected
        }

        std::cerr << "Failed to connect to server. Retrying in 5 seconds..." << std::endl;
        close(sock);
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Wait before retrying
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        std::cerr << "TLS handshake failed" << std::endl;
        return;
    }

    std::cout << "TLS connection established!" << std::endl;

    // Receive key (256-bit)
    uint8_t received_key[32];
    int bytes_read = SSL_read(ssl, received_key, sizeof(received_key));
    if (bytes_read != sizeof(received_key)) {
        std::cerr << "Failed to read full key" << std::endl;
        return;
    }

    std::cout << "Received key successfully!" << std::endl;

    // Store the key in the enclave
    sgx_status_t status = store_key(global_eid, received_key, sizeof(received_key));
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to store key in enclave" << std::endl;
    } else {
        std::cout << "Key stored securely in enclave." << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
}
void ocall_print(const char* str) {
    printf("%s\n", str);
}
int main() {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    initialize_ssl();
    receive_key_over_tls("172.17.0.1", 8080);
    return 0;
}


