#!/usr/bin/env bash

check_for_xcode() {
  if xcode-select -p >/dev/null 2>&1; then
    echo "Xcode Command Line Tools already installed: $(xcode-select -p)"
    return 0
  fi

  echo "Xcode Command Line Tools are required."

  if [ "${CI:-false}" = "true" ]; then
    echo "Cannot use interactive xcode-select --install in CI." >&2
    return 1
  fi

  echo "Opening installer..."
  if xcode-select --install; then
    echo "Installer opened. Re-run this script after installation completes."
  else
    echo "Failed to open installer, or installer is already active." >&2
  fi

  return 1
}

install_mac_libraries() {
  if ! check_for_xcode; then
    exit 1
  fi

  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required to install macOS packages." >&2
    echo "Install it from https://brew.sh/, add to PATH as instructed, and rerun this script." >&2
    return 1
  fi

  local packages=(
    wget
    s3cmd
    libxml2
    xmlstarlet
  )

  local package
  for package in "${packages[@]}"; do
    if brew list --formula "$package" >/dev/null 2>&1; then
      echo "ok: $package already installed"
      continue
    fi
    echo "Installing $package..."
    if ! brew install "$package"; then
      echo "error: failed to install $package" >&2
      return 1
    fi
  done
}

is_root() {
  [ "$(id -u)" -eq 0 ]
}

run_as_root() {
  if is_root; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "error: root privileges required and sudo not found" >&2
    return 1
  fi
  return 0
}

detect_linux_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v apk >/dev/null 2>&1; then
    echo "apk"
  else
    echo "unknown"
  fi
  return 0
}

install_linux_libraries() {
  local pkg_manager
  pkg_manager="$(detect_linux_package_manager)"

  echo "Package manager: $pkg_manager"

  case "$pkg_manager" in
    apt)
      run_as_root apt-get update
      run_as_root env DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
        apt-get install -y \
          git \
          make \
          wget \
          curl \
          unzip \
          tzdata \
          s3cmd \
          jq \
          bc \
          libxml2-utils \
          xmlstarlet \
          python3-pip \
          python3-venv \
          xxd \
          uuid-runtime \
          ca-certificates
      ;;

    dnf)
      run_as_root dnf install -y \
        git \
        make \
        wget \
        curl \
        unzip \
        tzdata \
        s3cmd \
        jq \
        bc \
        libxml2 \
        xmlstarlet \
        python3-pip \
        python3-virtualenv \
        vim-common \
        util-linux \
        ca-certificates
      ;;

    yum)
      run_as_root yum install -y \
        git \
        make \
        wget \
        curl \
        unzip \
        tzdata \
        s3cmd \
        jq \
        bc \
        libxml2 \
        xmlstarlet \
        python3-pip \
        python3-virtualenv \
        vim-common \
        util-linux \
        ca-certificates
      ;;

    apk)
      run_as_root apk add --no-cache \
        git \
        make \
        wget \
        curl \
        unzip \
        tzdata \
        s3cmd \
        jq \
        bc \
        libxml2-utils \
        xmlstarlet \
        py3-pip \
        python3 \
        py3-virtualenv \
        xxd \
        util-linux \
        ca-certificates
      ;;

    *)
      echo "error: unsupported Linux package manager" >&2
      return 1
      ;;
  esac
}

check_required_commands() {
  local commands=(
    git
    make
    wget
    curl
    unzip
    s3cmd
    jq
    bc
    xmllint
    xmlstarlet
    python3
    uuidgen
    xxd
  )

  local cmd
  for cmd in "${commands[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "error: required command not found: $cmd" >&2
      return 1
    fi
  done
}

os=$(uname -s)

case "$os" in
  Darwin)
    if ! install_mac_libraries; then
      echo "error installing MacOS packages" >&2
      exit 1
    fi
  ;;

  Linux)
    if ! install_linux_libraries; then
      echo "error installing Linux packages" >&2
      exit 1
    fi
  ;;

  *)
    echo "unsupported os type: $os" >&2
    exit 1
esac