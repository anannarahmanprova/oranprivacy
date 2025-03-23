FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# --- Step 1: Install system dependencies ---
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    golang \
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
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Step 2: Set SGX environment variables ---
ENV SGX_SDK=/opt/intel/sgxsdk/sgxsdk
ENV SGX_MODE=SIM
ENV SGX_ARCH=x64

# --- Step 3: Copy SGX SDK into the image ---
COPY sgxsdk $SGX_SDK

# --- Step 4: Set paths for SGX tools and libraries ---
ENV PATH="$SGX_SDK/bin/x64:$PATH"
ENV LD_LIBRARY_PATH="$SGX_SDK/lib64:$LD_LIBRARY_PATH"
ENV CGO_LDFLAGS="-L$SGX_SDK/lib64 -lsgx_urts_sim -lsgx_uae_service_sim -lpthread"

# --- Step 5: Set working directory ---
WORKDIR /app

# --- Step 6: Copy only required files ---

COPY pkg/monitoring /app

# --- Step 7: Build C++ SGX components ---
RUN make

# --- Step 8: Build Go binary ---
RUN go build -o sgxapp main.go

# --- Step 9: Expose port (optional) ---
EXPOSE 8080

# --- Step 10: Run SGX app ---
CMD ["./sgxapp"]

