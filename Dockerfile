# ==============================================================================
# KernelVault Multi-Stage Hermetic Build & Packaging Dockerfile
# ==============================================================================
# Stage 1: Build & Package Generator
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libgtest-dev \
    qt6-base-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

# Configure and compile in Release mode
RUN cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=ON \
    -DBUILD_GUI=ON

RUN cmake --build build --parallel

# Execute automated test suite to ensure correctness inside the container
RUN ctest --test-dir build --output-on-failure

# Generate official .deb and .tar.gz packages
RUN cpack --config build/CPackConfig.cmake -B /workspace/dist

# ==============================================================================
# Stage 2: Minimal Runtime Environment
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libqt6widgets6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

# Install the generated .deb package directly
COPY --from=builder /workspace/dist/*.deb /tmp/
RUN dpkg -i /tmp/*.deb && rm /tmp/*.deb

# Verify installed binary
RUN kvault --help

ENTRYPOINT ["kvault"]
CMD ["--help"]
