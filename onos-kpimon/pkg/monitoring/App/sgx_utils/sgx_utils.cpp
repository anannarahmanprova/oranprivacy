#include <cstdio>
#include <cstring>
#include "sgx_urts.h"
#include "sgx_utils.h"

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

/* Print SGX error code */
void print_error_message(sgx_status_t ret) {
    printf("SGX error code: %d\n", ret);
}

/* Initialize the SGX enclave */
int initialize_enclave(sgx_enclave_id_t* eid, const char* launch_token_path, const char* enclave_name) {
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    FILE* fp = fopen(launch_token_path, "rb");
    if (fp == NULL && (fp = fopen(launch_token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", launch_token_path);
    }

    if (fp != NULL) {
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", launch_token_path);
        }
    }

    ret = sgx_create_enclave(enclave_name, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    if (updated == FALSE || fp == NULL) {
        if (fp != NULL) fclose(fp);
        return 0;
    }

    fp = freopen(launch_token_path, "wb", fp);
    if (fp == NULL) return 0;

    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", launch_token_path);
    fclose(fp);
    return 0;
}

/* Check if an SGX ECALL was successful */
int is_ecall_successful(sgx_status_t sgx_status, const char* err_msg, sgx_status_t ecall_return_value) {
    if (sgx_status != SGX_SUCCESS || ecall_return_value != SGX_SUCCESS) {
        printf("%s\n", err_msg);
        print_error_message(sgx_status);
        print_error_message(ecall_return_value);
        return 0;
    }
    return 1;
}

