# syntax=docker/dockerfile:1.7

ARG CUDA_TAG=13.3.0-devel-rockylinux9
FROM --platform=linux/amd64 nvidia/cuda:${CUDA_TAG}

# Install build prerequisites and cuObject server development packages.
RUN set -eux; \
    dnf -y install 'dnf-command(config-manager)'; \
    dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/rhel9/x86_64/cuda-rhel9.repo; \
    dnf -y makecache; \
    dnf -y install \
      cuobjserver \
      libcuobjserver-devel \
      rdma-core-devel \
      numactl-libs \
      gcc \
      gcc-c++ \
      make \
      golang \
      git \
      findutils \
      which; \
    dnf clean all

WORKDIR /workspace

# Match current package install layout discovered in the NVIDIA Rocky image.
ENV CUOBJ_LIB_DIR=/usr/lib64
ENV CUOBJ_SERVER_INC_DIR=/usr/include
ENV VGWRDMA_RDMA_CGO_LDFLAGS="-L/usr/lib64 -Wl,-rpath,/usr/lib64 -Wl,-rpath-link,/usr/lib64"

# Default command builds vgwrdma in a mounted workspace checkout.
CMD ["bash", "-lc", "make vgwrdma CUOBJ_LIB_DIR=$CUOBJ_LIB_DIR CUOBJ_SERVER_INC_DIR=$CUOBJ_SERVER_INC_DIR VGWRDMA_RDMA_CGO_LDFLAGS=\"$VGWRDMA_RDMA_CGO_LDFLAGS\""]
