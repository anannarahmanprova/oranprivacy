ARG ONOS_BUILD_VERSION=undefined

FROM onosproject/golang-build:v1.3.0 as build

ENV GO111MODULE=on
ARG ONOS_MAKE_TARGET=build
# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    wget \
    curl \
    python3 \
    python3-pip \
    libssl-dev \
    libcurl4-openssl-dev \
    ocaml \
    autoconf \
    libtool \
    pkg-config \
    git \
    ca-certificates

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
RUN . /opt/intel/sgxsdk/sgxsdk/environment && \
    echo "SGX environment sourced"

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
COPY app/ /go/src/github.com/onosproject/onos-kpimon/app/


# Build C++ static library using Makefile
WORKDIR /go/src/github.com/onosproject/onos-kpimon/app
RUN make clean && make


# Build Go project with CGO enabled
WORKDIR /go/src/github.com/onosproject/onos-kpimon



ENV CC=gcc
ENV CXX=g++

ENV CGO_ENABLED=1
ENV CFLAGS="-Wno-error"
ENV CXXFLAGS="-Wno-error"
ENV CGO_CFLAGS="-Wno-error -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc"

ENV CGO_LDFLAGS="-L/opt/intel/sgxsdk/sgxsdk/lib64 \
-lsgx_urts_sim \
-lsgx_uae_service_sim \
-lpthread \
-lstdc++"






# RUN cd /usr/local/go/src && ./make.bash



RUN cd /go/src/github.com/onosproject/onos-kpimon && GOFLAGS=-mod=vendor make ${ONOS_MAKE_TARGET}

# Final Minimal Image

FROM frolvlad/alpine-glibc:alpine-3.12

# Use non-root user
USER nobody

# Set working directory (must be writable for enclave.token)
WORKDIR /tmp

# Copy compiled Go binary
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/build/_output/onos-kpimon /usr/local/bin/onos-kpimon

# Copy enclave binary + SGX simulation libs
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/app/enclave.signed.so /tmp/enclave.signed.so
COPY --from=build /opt/intel/sgxsdk/sgxsdk/lib64/ /usr/local/lib/
COPY --from=build /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/local/lib/libstdc++.so.6

# Optional: suppress enclave.token warnings
RUN touch /tmp/enclave.token && chmod 666 /tmp/enclave.token

# Set runtime env vars
ENV SGX_MODE=SIM
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Expose ports
EXPOSE 19999
EXPOSE 5150

# Run the xApp
ENTRYPOINT ["/usr/local/bin/onos-kpimon"]
