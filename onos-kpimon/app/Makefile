######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
		SGX_COMMON_CFLAGS += -O0 -g
else
		SGX_COMMON_CFLAGS += -O2
endif

######## Shared and Static Library Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif
App_Cpp_Files := App/App.cpp App/sgx_utils/sgx_utils.cpp

App_Include_Paths := -IApp -I$(SGX_SDK)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := -shared $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread
App_Link_Flags += -lsgx_uae_service_sim
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_UC_File := App/Enclave_u.c
App_UO_File := App/Enclave_u.o
Shared_Lib := libbridge.so
Static_Lib := App/libbridge.a

######## Enclave Settings ########

Trts_Library_Name := sgx_trts_sim
Service_Library_Name := sgx_tservice_sim
Crypto_Library_Name := sgx_tcrypto
Enclave_Cpp_Files := Enclave/Enclave.cpp Enclave/Sealing/Sealing.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0


Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_TC_File := Enclave/Enclave_t.c
Enclave_TO_File := Enclave/Enclave_t.o
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
App_Name := app
.PHONY: all clean

all: $(App_Name) $(Shared_Lib) $(Static_Lib) $(Signed_Enclave_Name)

######## Shared and Static Library Build ########

$(Shared_Lib): $(App_Cpp_Objects) $(App_UO_File)
	@$(CXX) -o $@ $^ $(App_Link_Flags)
	@echo "LINK =>  $@"

$(Static_Lib): $(App_Cpp_Objects) $(App_UO_File)
	@ar rcs $@ $^
	@echo "AR   =>  $@"

######## EDL File Generation ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

######## Clean ########

clean:
	@rm -f $(Shared_Lib) $(Static_Lib) $(App_Cpp_Objects) $(App_UC_File) $(App_UO_File) \
	$(Enclave_Cpp_Objects) $(Enclave_TC_File) $(Enclave_TO_File) $(Enclave_Name) $(Signed_Enclave_Name)
	@echo "CLEAN => All build files removed."

