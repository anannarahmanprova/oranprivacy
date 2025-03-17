ARG ONOS_BUILD_VERSION=undefined

FROM onosproject/golang-build:v1.3.0 as build

ENV GO111MODULE=on
ARG ONOS_MAKE_TARGET=build
# Install dependencies
RUN apt update && apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    protobuf-compiler \
    autoconf \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*



# Set environment variables for Go
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH



# Set SGX SDK Path and Environment Variables
ENV SGX_SDK=/opt/intel/sgxsdk/sgxsdk
ENV SGX_MODE=SIM
ENV SGX_ARCH=x64
ENV C_INCLUDE_PATH=/opt/intel/sgxsdk/sgxsdk/include
ENV CPLUS_INCLUDE_PATH=/opt/intel/sgxsdk/sgxsdk/include
ENV LD_LIBRARY_PATH=/opt/intel/sgxsdk/sgxsdk/lib64:$LD_LIBRARY_PATH


# Copy SGX SDK
COPY sgxsdk /opt/intel/sgxsdk/sgxsdk


# Set Bash as the default shell
SHELL ["/bin/bash", "-c"]

# Ensure SGX SDK is sourced correctly
RUN echo '. /opt/intel/sgxsdk/sgxsdk/environment' >> ~/.bashrc && \
    . ~/.bashrc


# Verify SGX SDK installation
RUN ls -l /opt/intel/sgxsdk/sgxsdk/include/sgx_edger8r.h
RUN ls -l /opt/intel/sgxsdk/sgxsdk/bin/x64
RUN . $SGX_SDK/environment && echo "SGX environment sourced"

# Verify SGX SDK installation

RUN ls -l /opt/intel/sgxsdk/sgxsdk/include/tlibc/mbusafecrt.h

# Copy Source Files
COPY Makefile go.mod go.sum /go/src/github.com/onosproject/onos-kpimon/
COPY cmd/ /go/src/github.com/onosproject/onos-kpimon/cmd/
COPY pkg/ /go/src/github.com/onosproject/onos-kpimon/pkg/
COPY vendor/ /go/src/github.com/onosproject/onos-kpimon/vendor/
COPY api/ /go/src/github.com/onosproject/onos-kpimon/api
COPY build/ /go/src/github.com/onosproject/onos-kpimon/build/



# Build C++ static library using Makefile
WORKDIR /go/src/github.com/onosproject/onos-kpimon/pkg/monitoring
RUN make clean && make


# Build Go project with CGO enabled
WORKDIR /go/src/github.com/onosproject/onos-kpimon





ENV CGO_ENABLED=1
ENV CFLAGS="-Wno-error"
ENV CXXFLAGS="-Wno-error"
ENV CGO_CFLAGS="-Wl,--allow-multiple-definition -Wno-error  -I/go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport"
ENV CGO_LDFLAGS="-L/opt/intel/sgxsdk/sgxsdk/lib64 \
-lsgx_trts_sim \
-lsgx_tservice_sim \
-lsgx_tcrypto \
-lsgx_tcxx \
-lsgx_tstdc \
-lc \
-Wl,--no-undefined \
-Wl,--defsym,__ImageBase=0 \
-Wl,--allow-multiple-definition \
-Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
-Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,-z,notext"








RUN echo "Searching for gcc_fatalf.c..." && \
    FILE=$(find / -name "gcc_fatalf.c" 2>/dev/null) && \
    if [ -n "$FILE" ]; then \
        echo "File found at: $FILE" && \
        echo "---- File Content ----" && \
        cat "$FILE"; \
    else \
        echo "File not found."; \
    fi



# RUN cd /usr/local/go/src && ./make.bash



RUN echo "Starting build with debugging..." && \
    echo "CGO_CFLAGS: $CGO_CFLAGS" && \
    echo "CGO_LDFLAGS: $CGO_LDFLAGS" && \
    echo "GOFLAGS: $GOFLAGS" && \
    echo "SGX_SDK: $SGX_SDK" && \
    echo "SGX Mode: $SGX_MODE" && \
    echo "CFLAGS: $CFLAGS" && \
    echo "Current Directory: $(pwd)" && \
    echo "Directory Structure:" && \
    ls -la && \
    echo "Checking GCC includes..." && \
    echo '#include <stdio.h>' | gcc -E - > /dev/null || echo "stdio.h not found" && \
    echo "Running 'make' with debugging enabled..." && \
    CFLAGS+="-Wno-error" make --debug=v ${ONOS_MAKE_TARGET} || { echo "Make build failed"; exit 1; }

# Final Minimal Image
FROM frolvlad/alpine-glibc:alpine-3.12
USER nobody

# Copy compiled binaries and libraries
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/build/_output/onos-kpimon /usr/local/bin/onos-kpimon
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/libbridge.so /usr/local/lib/libbridge.so
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App/libbridge.a /usr/local/lib/libbridge.a
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App/App.h /usr/local/include/App.h

# Set environment variables for runtime
ENV CGO_ENABLED=1
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV CGO_LDFLAGS="-L/usr/local/lib -lbridge"

# Expose ports
EXPOSE 19999
EXPOSE 5150

# Entry point for the application
ENTRYPOINT ["onos-kpimon"]

