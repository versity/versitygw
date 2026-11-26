# syntax=docker/dockerfile:1.7

FROM --platform=linux/amd64 rockylinux:9

# Install build prerequisites for host-memory RDMA cuobjtest mode.
RUN --mount=type=bind,source=tests/retry.sh,target=/usr/local/bin/retry \
    set -eux; \
    retry dnf -y install \
      rdma-core-devel \
      gcc \
      gcc-c++ \
      make \
      golang \
      git \
      findutils \
      which; \
    dnf clean all

WORKDIR /workspace

# Default command builds host-mode cuobjtest in a mounted workspace checkout.
CMD ["bash", "-lc", "tests/retry.sh go mod download && make cuobjtest-host"]
