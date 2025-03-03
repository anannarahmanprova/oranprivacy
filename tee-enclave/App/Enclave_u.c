#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_store_key_t {
	uint8_t* ms_key;
	size_t ms_len;
} ms_store_key_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t store_key(sgx_enclave_id_t eid, uint8_t* key, size_t len)
{
	sgx_status_t status;
	ms_store_key_t ms;
	ms.ms_key = key;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

