// main.go
package main

/*
#cgo CFLAGS: -I/path/to/intel/sgx/include
#cgo LDFLAGS: -L/path/to/intel/sgx/lib64 -lsgx_urts
#include <stdlib.h>
#include "sgx_urts.h"
#include "Enclave_u.h"

// Wrapper to call the enclave function to process a command.
sgx_status_t call_ecall_process_command(sgx_enclave_id_t eid, const char* command) {
    return ecall_process_command(eid, command);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
	var eid C.sgx_enclave_id_t

	// Convert enclave filename to C string.
	enclaveFile := C.CString("enclave.signed.so")
	defer C.free(unsafe.Pointer(enclaveFile))

	// Create the enclave (debug flag set to 1 for development).
	ret := C.sgx_create_enclave(enclaveFile, C.uint(1), nil, nil, &eid, nil)
	if ret != C.SGX_SUCCESS {
		fmt.Printf("Failed to create enclave: 0x%x\n", ret)
		return
	}

	// Simulate receiving a command from the E2 agent control logic.
	// In a production system, this data might come over a secure channel.
	command := C.CString("Activate feature X")
	defer C.free(unsafe.Pointer(command))

	// Call the enclave function to process the command.
	ret = C.call_ecall_process_command(eid, command)
	if ret != C.SGX_SUCCESS {
		fmt.Printf("ECALL process command failed: 0x%x\n", ret)
	}

	// Destroy the enclave when done.
	C.sgx_destroy_enclave(eid)
}
