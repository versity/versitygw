# syntax=docker/dockerfile:1.7

ARG CUDA_TAG=13.3.0-devel-rockylinux9
FROM --platform=linux/amd64 nvidia/cuda:${CUDA_TAG}

ARG CUDA_TAG
ARG CUOBJCLIENT_PKG_SUFFIX=

# Install build prerequisites and cuObject client development packages.
RUN set -eux; \
    cuda_version="${CUDA_TAG%%-*}"; \
    cuda_suffix="$(printf '%s' "$cuda_version" | awk -F. '{print $1"-"$2}')"; \
    pkg_suffix="${CUOBJCLIENT_PKG_SUFFIX:-$cuda_suffix}"; \
    dnf -y install 'dnf-command(config-manager)'; \
    dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/rhel9/x86_64/cuda-rhel9.repo; \
    dnf -y makecache; \
    dnf -y install \
      libcuobjclient-${pkg_suffix} \
      libcuobjclient-devel-${pkg_suffix} \
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
ENV CUOBJ_LIB_DIR=/usr/local/cuda/targets/x86_64-linux/lib
ENV CUOBJ_CLIENT_INC_DIR=/usr/include
ENV CUOBJ_CUDA_INC_DIR=/usr/local/cuda/include
ENV CUOBJCLIENT_CGO_LDFLAGS="-L/usr/local/cuda/targets/x86_64-linux/lib -Wl,-rpath,/usr/local/cuda/targets/x86_64-linux/lib -Wl,-rpath-link,/usr/local/cuda/targets/x86_64-linux/lib"

# Default command builds GPU-mode cuobjtest in a mounted workspace checkout.
CMD ["bash", "-lc", "make cuobjtest-gpu CUOBJ_LIB_DIR=$CUOBJ_LIB_DIR CUOBJ_CLIENT_INC_DIR=$CUOBJ_CLIENT_INC_DIR CUOBJ_CUDA_INC_DIR=$CUOBJ_CUDA_INC_DIR CUOBJCLIENT_CGO_LDFLAGS=\"$CUOBJCLIENT_CGO_LDFLAGS\""]
