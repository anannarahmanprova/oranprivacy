ARG ONOS_BUILD_VERSION=undefined

FROM onosproject/golang-build:v1.3.0 as build

ENV GO111MODULE=on
ARG ONOS_MAKE_TARGET=build

# Install only essential packages
RUN apt update && apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set the SGX SDK path
# Set the SGX SDK path
ENV SGX_SDK=/opt/intel/sgxsdk

# Copy SGX SDK (relative path inside the context)
COPY sgxsdk /opt/intel/sgxsdk


# Verify SGX SDK
RUN ls -l /opt/intel/sgxsdk/include/sgx_edger8r.h

# Copy Go and C++ source code
COPY Makefile go.mod go.sum /go/src/github.com/onosproject/onos-kpimon/
COPY cmd/ /go/src/github.com/onosproject/onos-kpimon/cmd/
COPY pkg/ /go/src/github.com/onosproject/onos-kpimon/pkg/
COPY vendor/ /go/src/github.com/onosproject/onos-kpimon/vendor/
COPY api/ /go/src/github.com/onosproject/onos-kpimon/api
COPY build/ /go/src/github.com/onosproject/onos-kpimon/build/

# Build C++ static library
WORKDIR /go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App

# Build C++ static library and verify the output
RUN g++ -c -fPIC -I${SGX_SDK}/include -I/go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App App.cpp -o App.o && \
    ar rcs libbridge.a App.o && \
    ls -la && \
    nm libbridge.a
    
# Build Go project with CGO enabled
WORKDIR /go/src/github.com/onosproject/onos-kpimon
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App -I${SGX_SDK}/include"
ENV CGO_LDFLAGS="-L/go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App -lbridge"
RUN GOFLAGS=-mod=vendor make ${ONOS_MAKE_TARGET}

# ========================
# Stage 2: Final Minimal Image
# ========================
FROM frolvlad/alpine-glibc:alpine-3.12

USER nobody

# Copy the built Go binary and C++ static library
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/build/_output/onos-kpimon /usr/local/bin/onos-kpimon
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App/libbridge.a /usr/local/lib/libbridge.a
COPY --from=build /go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App/App.h /usr/local/include/App.h

# Set runtime environment variables
ENV CGO_ENABLED=1
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV CGO_LDFLAGS="-L/usr/local/lib -lbridge"

EXPOSE 19999
EXPOSE 5150

ENTRYPOINT ["onos-kpimon"]

