#!/usr/bin/env bash

pre_install_report() {
  local os arch cwd detected_pkg_manager xcode_clt cmd

  os=$(uname -s)
  arch=$(uname -m)
  cwd=$(pwd)
  detected_pkg_manager="$(detect_linux_package_manager)"

  echo "=== Pre-install report ==="
  printf "OS: %s\n" "$os"
  printf "Architecture: %s\n" "$arch"
  printf "Working directory: %s\n" "$cwd"
  printf "Current user: %s (uid=%s)\n" "$(id -un)" "$(id -u)"
  printf "Root user: %s\n" "$(is_root && echo yes || echo no)"
  printf "CI: %s\n" "${CI:-false}"
  printf "PATH: %s\n" "$PATH"
  printf "Home: %s\n" "$HOME"

  if [ "$os" = "Linux" ]; then
    printf "Detected Linux package manager: %s\n" "$detected_pkg_manager"
  elif [ "$os" = "Darwin" ]; then
    if command -v xcode-select >/dev/null 2>&1 && xcode-select -p >/dev/null 2>&1; then
      xcode_clt=$(xcode-select -p)
      printf "Xcode CLT: %s\n" "$xcode_clt"
    else
      printf "Xcode CLT: not installed\n"
    fi
  fi

  for cmd in bash brew go aws bats git make curl wget unzip jq python3 xmllint xmlstarlet s3cmd uuidgen xxd; do
    if command -v "$cmd" >/dev/null 2>&1; then
      printf "%-10s %s\n" "$cmd:" "$(command -v "$cmd")"
    else
      printf "%-10s %s\n" "$cmd:" "missing"
    fi
  done

  if command -v bash >/dev/null 2>&1; then
    printf "Bash version: %s\n" "$BASH_VERSION"
  fi
  if command -v go >/dev/null 2>&1; then
    printf "Go version: %s\n" "$(go version)"
  fi
  if command -v aws >/dev/null 2>&1; then
    printf "AWS CLI version: %s\n" "$(aws --version 2>&1)"
  fi
  if command -v bats >/dev/null 2>&1; then
    printf "BATS version: %s\n" "$(bats --version 2>&1)"
  fi
  echo "=========================="
  return 0
}

check_for_xcode() {
  local xcode_tools

  if xcode-select -p >/dev/null 2>&1; then
    xcode_tools=$(xcode-select -p)
    printf "Xcode Command Line Tools already installed: %s\n" "$xcode_tools"
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

install_managed_libraries() {
  if [ "$#" -ne 1 ]; then
    echo "install_managed_libraries requires OS type" >&2
    return 1
  fi
  local os="$1"
  case "$os" in
  Darwin)
    if ! install_mac_libraries; then
      echo "error installing mac libraries" >&2
      return 1
    fi
    ;;
  Linux)
    if ! install_linux_libraries; then
      echo "error installing linux libraries" >&2
      return 1
    fi
    ;;
  *)
    echo "unrecognized os: $os" >&2
    return 1
    ;;
  esac
  return 0
}

install_linux_libraries() {
  local package_manager

  package_manager="$(detect_linux_package_manager)"
  case "$package_manager" in
  apt)
    if ! install_apt_libraries; then
      echo "error installing apt libraries" >&2
      return 1
    fi
    ;;
  dnf)
    if ! install_dnf_libraries; then
      echo "error installing dnf libraries" >&2
      return 1
    fi
    ;;
  yum)
    if ! install_yum_libraries; then
      echo "error installing yum libraries" >&2
      return 1
    fi
    ;;
  apk)
    if ! install_apk_libraries; then
      echo "error installing apk libraries" >&2
      return 1
    fi
    ;;
  *)
    echo "unrecognized package manager: '$package_manager'" >&2
    return 1
    ;;
  esac
  return 0
}

install_mac_libraries() {
  if ! check_for_xcode; then
    return 1
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
    jq
    go
    bats-core
  )
  if command -v aws >/dev/null 2>&1; then
    printf "AWS CLI already installed: %s\n" "$(aws --version 2>&1)"
  else
    packages+=(awscli)
  fi

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

  if ! upgrade_bash_on_mac; then
    echo "error upgrading bash" >&2
    return 1
  fi
  return 0
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
  # just returns specific error code from command run as root
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

install_apt_libraries() {
  local libraries=(git
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
                   ca-certificates \
                   build-essential \
                   libc6-dev \
                   bats)
  if command -v go >/dev/null 2>&1; then
    printf "Go already installed: %s\n" "$(go version)"
  else
    libraries+=(golang-go)
  fi
  run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update || return 1
  run_as_root env DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y "${libraries[@]}"
}

install_dnf_libraries() {
  local libraries=(git \
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
                   ca-certificates \
                   bats)
  if command -v go >/dev/null 2>&1; then
    printf "Go already installed: %s\n" "$(go version)"
  else
    libraries+=(golang)
  fi
  run_as_root dnf install -y "${libraries[@]}"
}

install_yum_libraries() {
  local libraries=(git \
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
                   ca-certificates \
                   bats)
  if command -v go >/dev/null 2>&1; then
    printf "Go already installed: %s\n" "$(go version)"
  else
    libraries+=(golang)
  fi
  run_as_root yum install -y "${libraries[@]}"
}

install_apk_libraries() {
  local libraries=(git \
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
                 ca-certificates \
                 bats)
  if command -v go >/dev/null 2>&1; then
    printf "Go already installed: %s\n" "$(go version)"
  else
    libraries+=(go)
  fi
  run_as_root apk add --no-cache "${libraries[@]}"
}

check_required_commands() {
  local commands=(
    aws
    go
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

  if [ "${INSTALL_MC:-false}" = "true" ]; then
    commands+=(mc)
  fi

  local cmd
  for cmd in "${commands[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "error: required command not found: $cmd" >&2
      return 1
    fi
  done
  return 0
}

upgrade_bash_on_mac() {
  local bash_major brew_bash bash_path

  bash_major="${BASH_VERSINFO[0]:-0}"
  if [ "$bash_major" -ge 4 ]; then
    printf "Bash already modern enough: %s\n" "$BASH_VERSION"
    return 0
  fi

  if ! command -v brew >/dev/null 2>&1; then
    echo "error: Homebrew is required to upgrade Bash on macOS" >&2
    return 1
  fi

  echo "Upgrading bash with Homebrew..."
  if ! brew install bash; then
    echo "error: failed to install bash with Homebrew" >&2
    return 1
  fi

  if brew --prefix >/dev/null 2>&1; then
    brew_bash="$(brew --prefix)/bin/bash"
    if [ -x "$brew_bash" ]; then
      bash_path="$brew_bash"
    fi
  fi
  if [ -z "$bash_path" ] && command -v bash >/dev/null 2>&1; then
    bash_path="$(command -v bash)"
  fi

  if [ -n "$bash_path" ] && [ -x "$bash_path" ]; then
    printf "Installed newer bash: %s\n" "$bash_path"
    printf "Use this shell explicitly if needed: %s\n" "$bash_path"
    return 0
  fi

  echo "error: bash install completed but upgraded bash path could not be found" >&2
  return 1
}

install_aws_from_url() {
  if [ "$#" -ne 2 ]; then
    echo "install_aws_from_url requires download url, archive name" >&2
    return 1
  fi
  local download_url="$1" archive_name="$2"
  local tmp_dir install_dir bin_dir

  tmp_dir=$(mktemp -d) || return 1
  install_dir="/usr/local/aws-cli"
  bin_dir="/usr/local/bin"

  echo "Downloading AWS CLI from $download_url..."
  if ! curl -fsSL "$download_url" -o "$tmp_dir/$archive_name"; then
    echo "error: failed to download AWS CLI" >&2
    rm -rf "$tmp_dir"
    return 1
  fi
  if ! unzip -q "$tmp_dir/$archive_name" -d "$tmp_dir"; then
    echo "error: failed to unzip AWS CLI archive" >&2
    rm -rf "$tmp_dir"
    return 1
  fi
  if ! run_as_root "$tmp_dir/aws/install" -i "$install_dir" -b "$bin_dir" --update; then
    echo "error: failed to install AWS CLI" >&2
    rm -rf "$tmp_dir"
    return 1
  fi
  rm -rf "$tmp_dir"
}

install_linux_aws_command_line_tools() {
  if command -v aws >/dev/null 2>&1; then
    printf "AWS CLI already installed: %s\n" "$(aws --version 2>&1)"
    return 0
  fi
  local response tmp_dir archive_name download_url

  archive_name="awscliv2.zip"
  case "$(uname -m)" in
    x86_64|amd64)
      download_url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
      ;;
    aarch64|arm64)
      download_url="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"
      ;;
    *)
      echo "error: unsupported Linux architecture for AWS CLI: $(uname -m)" >&2
      rm -rf "$tmp_dir"
      return 1
      ;;
  esac
  if ! install_aws_from_url "$download_url" "$archive_name"; then
    echo "error installing AWS from download url '$download_url'"
    return 1
  fi

  if ! command -v aws >/dev/null 2>&1; then
    echo "error: AWS CLI still not found after installation" >&2
    return 1
  fi

  if ! response=$(aws --version 2>&1); then
    echo "error: failed to run installed AWS CLI" >&2
    return 1
  fi
  printf "Installed AWS CLI: %s\n" "$response"
  return 0
}

get_mc_download_link() {
  if [ $# -ne 1 ]; then
    echo "get_mc_download_link requires os" >&2
    return 1
  fi
  local os="$1"
  local arch download_url

  arch=$(uname -m)
  case "$os" in
    Darwin)
      case "$arch" in
        x86_64|amd64)
          download_url="https://dl.min.io/client/mc/release/darwin-amd64/mc"
          ;;
        arm64|aarch64)
          download_url="https://dl.min.io/client/mc/release/darwin-arm64/mc"
          ;;
        *)
          echo "error: unsupported macOS architecture for mc: $arch" >&2
          return 1
          ;;
      esac
      ;;
    Linux)
      case "$arch" in
        x86_64|amd64)
          download_url="https://dl.min.io/client/mc/release/linux-amd64/mc"
          ;;
        arm64|aarch64)
          download_url="https://dl.min.io/client/mc/release/linux-arm64/mc"
          ;;
        *)
          echo "error: unsupported Linux architecture for mc: $arch" >&2
          return 1
          ;;
      esac
      ;;
    *)
      echo "error: unsupported OS type for installing mc: $os" >&2
      return 1
      ;;
  esac
  printf '%s\n' "$download_url"
  return 0
}

install_mc() {
  if [ "$#" -ne 1 ]; then
    echo "install_mc requires os" >&2
    return 1
  fi
  local os="$1"
  local download_url tmp_dir target_path response

  if command -v mc >/dev/null 2>&1; then
    printf "MinIO mc already installed: %s\n" "$(mc --version 2>&1 | head -n 1)"
    return 0
  fi

  if ! response=$(get_mc_download_link "$os" 2>&1); then
    echo "error getting mc download link: $response" >&2
    return 1
  fi
  download_url="$response"

  tmp_dir=$(mktemp -d) || return 1
  target_path="/usr/local/bin/mc"
  echo "Downloading mc from $download_url..."
  if ! curl -fsSL "$download_url" -o "$tmp_dir/mc"; then
    echo "error: failed to download mc" >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  if ! chmod 755 "$tmp_dir/mc"; then
    echo "error: failed to mark mc executable" >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  if ! run_as_root install "$tmp_dir/mc" "$target_path"; then
    echo "error: failed to install mc to $target_path" >&2
    rm -rf "$tmp_dir"
    return 1
  fi
  rm -rf "$tmp_dir"

  if ! command -v mc >/dev/null 2>&1; then
    echo "error: mc still not found after installation" >&2
    return 1
  fi

  if ! response=$(mc --version 2>&1 | head -n 1); then
    echo "error: failed to run installed mc" >&2
    return 1
  fi
  printf "Installed MinIO mc: %s\n" "$response"
  return 0
}

os=$(uname -s)

pre_install_report

if ! install_managed_libraries "$os"; then
  echo "error installing package-managed libraries" >&2
  exit 1
fi

if ! response=$(go get -v -t -d ./... 2>&1); then
  printf "error installing go dependencies: %s\n" "$response"
  exit 1
fi

if [ "$os" == "Linux" ] && ! install_linux_aws_command_line_tools; then
  exit 1
fi

if [ "${INSTALL_MC:-false}" = "true" ]; then
  if ! install_mc "$os"; then
    exit 1
  fi
else
  echo "Skipping mc installation (set INSTALL_MC=true to enable)"
fi

tests_folder="$(dirname "${BASH_SOURCE[0]}")"
if [ -d "${tests_folder}/bats-support" ]; then
  echo "bats-support already installed"
else
  if ! git clone https://github.com/bats-core/bats-support.git "${tests_folder}/bats-support"; then
    echo "error getting bats-support library" >&2
    exit 1
  fi
fi
if [ -d "${tests_folder}/bats-assert" ]; then
  echo "bats-assert already installed"
else
  if ! git clone https://github.com/ztombol/bats-assert.git "${tests_folder}/bats-assert"; then
    echo "error getting bats-assert library" >&2
    exit 1
  fi
fi

if ! check_required_commands; then
  exit 1
fi

echo "Install complete"
exit 0
