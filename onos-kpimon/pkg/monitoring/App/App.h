#ifndef APP_H
#define APP_H

#include <stdio.h>
#include <iostream>
#include "sgx_urts.h"
#include "Enclave_u.h"

#include "sgx_utils/sgx_utils.h"


#ifdef __cplusplus
extern "C" {
#endif

int initialize_enclave(const char* enclave_path);
int destroy_enclave();
int process_kpi_wrapper(uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // APP_H

