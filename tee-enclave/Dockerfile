# Base image
FROM ubuntu:20.04

# Set non-interactive mode
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt update && apt install -y \
    build-essential \
    cmake \
    python3 \
    python3-pip \
    libssl-dev \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    protobuf-compiler \
    ocaml \
    ocamlbuild \
    autoconf \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the SGX SDK
COPY sgxsdk /opt/intel/sgxsdk
ENV SGX_SDK=/opt/intel/sgxsdk

# Set Bash as the default shell
SHELL ["/bin/bash", "-c"]

# Ensure SGX SDK is sourced correctly
RUN echo '. /opt/intel/sgxsdk/sgxsdk/environment' >> ~/.bashrc && \
    . ~/.bashrc

# Copy the application
COPY . /app

ENV LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

# Build the SGX application
RUN make clean && make

# Expose necessary ports
EXPOSE 8080

# Set default command
#CMD ["./app"]
CMD ["sh", "-c", "./app && tail -f /dev/null"]
