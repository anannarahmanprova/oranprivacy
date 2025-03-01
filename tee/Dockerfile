# Use Ubuntu 22.04 as the builder base image
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Install Go and necessary dependencies
RUN apt-get update && apt-get install -y golang gcc g++ make cmake git curl wget build-essential && rm -rf /var/lib/apt/lists/*

# Copy SGX SDK into the container
COPY sgxsdk /opt/intel/sgxsdk

# Set up SGX environment
ENV SGX_SDK=/opt/intel/sgxsdk
ENV PATH="$SGX_SDK/bin:$PATH"
ENV LD_LIBRARY_PATH="$SGX_SDK/lib64:$LD_LIBRARY_PATH"

# Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code and build the Go application
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o ric_tee_app main.go

# Final stage: Create a minimal runtime image
FROM ubuntu:22.04
COPY --from=builder /app/ric_tee_app /usr/local/bin/ric_tee_app

ENTRYPOINT ["/usr/local/bin/ric_tee_app"]
