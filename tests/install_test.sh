#!/usr/bin/env bash

source ./tests/download_dependencies.sh

export AWS_ARCHIVE_NAME="awscliv2.zip"

DOWNLOAD_ONLY_FOLDER=""
INSTALL_ONLY_FOLDER=""

show_help() {
  echo "Usage: $0 [--download-only <folder>] [--install-only <folder>]"
  echo "  --download-only <folder>  Download dependency artifacts into <folder>"
  echo "  --install-only <folder>   Install dependency artifacts from <folder>"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h|--help)
        show_help
        exit 0
        ;;
      --download-only)
        if [ -z "$2" ]; then
          echo "error: --download-only requires a folder argument" >&2
          return 1
        fi
        DOWNLOAD_ONLY_FOLDER="$2"
        shift 2
        ;;
      --install-only)
        if [ -z "$2" ]; then
          echo "error: --install-only requires a folder argument" >&2
          return 1
        fi
        INSTALL_ONLY_FOLDER="$2"
        shift 2
        ;;
      *)
        echo "error: unknown argument '$1'" >&2
        show_help >&2
        return 1
        ;;
    esac
  done

  if [ -n "$DOWNLOAD_ONLY_FOLDER" ] && [ -n "$INSTALL_ONLY_FOLDER" ]; then
    echo "error: --download-only and --install-only cannot be used together" >&2
    return 1
  fi
  return 0
}

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
  printf "Download-only folder: %s\n" "${DOWNLOAD_ONLY_FOLDER:-unset}"
  printf "Install-only folder: %s\n" "${INSTALL_ONLY_FOLDER:-unset}"

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

run_apt_update_and_install() {
  if [ $# -le 0 ]; then
    echo "run_apt_update_and_install requires libraries" >&2
    return 1
  fi
  local libraries=("$@")

  run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update || return 1
  run_as_root env DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y "${libraries[@]}" || return 1
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
  if [ -z "$DOWNLOAD_ONLY_FOLDER" ]; then
    if [ -z "$INSTALL_ONLY_FOLDER" ]; then
      run_apt_update_and_install "${libraries[@]}" || return 1
    else
      local install_result=0
      run_as_root env DEBIAN_FRONTEND=noninteractive apt install -y "$(realpath -m "$INSTALL_ONLY_FOLDER")"/apt/*.deb || install_result=$?
      # if install from packages fails, fall back
      if [ "$install_result" -ne 0 ]; then
        run_apt_update_and_install "${libraries[@]}" || return 1
      fi
    fi
  else
    if ! download_apt_packages "$DOWNLOAD_ONLY_FOLDER" "${libraries[@]}"; then
      echo "error downloading apt packages" >&2
      return 1
    fi
  fi
  return 0
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

install_aws_cli() {
  if [ "$#" -ne 1 ]; then
    echo "install_aws requires archive location" >&2
    return 1
  fi
  local archive_location="$1"
  local tmp_dir install_dir bin_dir

  tmp_dir=$(mktemp -d)
  install_dir="/usr/local/aws-cli"
  bin_dir="/usr/local/bin"

  if ! unzip -q "$archive_location" -d "$tmp_dir"; then
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
  return 0
}

download_and_install_aws_cli() {
  local response package_location

  if command -v aws >/dev/null 2>&1; then
    printf "AWS CLI already installed: %s\n" "$(aws --version 2>&1)"
    return 0
  fi
  if [ -z "$INSTALL_ONLY_FOLDER" ]; then
    if ! response=$(download_aws "$DOWNLOAD_ONLY_FOLDER" 2>&1); then
      echo "error downloading aws package: $response" >&2
      return 1
    fi
    package_location="$response"
  else
    package_location="$INSTALL_ONLY_FOLDER/aws/$AWS_ARCHIVE_NAME"
  fi
  printf '%s\n' "aws package location: $package_location"
  if [ -z "$DOWNLOAD_ONLY_FOLDER" ]; then
    if ! install_aws_cli "$package_location"; then
      echo "error installing aws cli" >&2
      return 1
    fi
  fi
  return 0
}

download_and_install_mc() {
  if [ $# -ne 1 ]; then
    echo "download_and_install_mc requires os" >&2
    return 1
  fi
  local os="$1"
  local response package_location

  if command -v mc >/dev/null 2>&1; then
    printf "MinIO mc already installed: %s\n" "$(mc --version 2>&1 | head -n 1)"
    return 0
  fi
  if [ -z "$INSTALL_ONLY_FOLDER" ]; then
    if ! response=$(download_mc "$os" "$DOWNLOAD_ONLY_FOLDER" 2>&1); then
      echo "error downloading mc package: $response" >&2
      return 1
    fi
    package_location="$response"
  else
    package_location="$INSTALL_ONLY_FOLDER/mc/mc"
  fi
  printf 'mc package location: %s\n' "$package_location"
  if [ -z "$DOWNLOAD_ONLY_FOLDER" ]; then
    if ! install_mc "$package_location"; then
      echo "error installing mc" >&2
      return 1
    fi
  fi
  return 0
}

install_mc() {
  if [ "$#" -ne 1 ]; then
    echo "install_aws requires mc install script location" >&2
    return 1
  fi
  local mc_location="$1"
  local target_path="/usr/local/bin/mc" response

  if ! run_as_root install "$mc_location" "$target_path"; then
    echo "error: failed to install mc to $target_path" >&2
    rm -rf "$mc_location"
    return 1
  fi
  rm -rf "$mc_location"

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

download_and_install_bats_helpers() {
  local download_folder

  if [ -z "$INSTALL_ONLY_FOLDER" ]; then
    if [ -n "$DOWNLOAD_ONLY_FOLDER" ]; then
      download_folder="$DOWNLOAD_ONLY_FOLDER/bats-helpers"
    else
      download_folder="$(dirname "${BASH_SOURCE[0]}")"
    fi
    if ! download_bats_helpers "$download_folder"; then
      echo "error downloading bats helpers" >&2
      return 1
    fi
  fi
  if [ -z "$DOWNLOAD_ONLY_FOLDER" ]; then
    destination_folder="$(dirname "${BASH_SOURCE[0]}")"
    if [ -d "${destination_folder}/bats-support" ]; then
      echo "bats-support already installed"
    else
      if ! mv "$INSTALL_ONLY_FOLDER/bats-helpers/bats-support" "${destination_folder}/bats-support"; then
        echo "error installing bats-support"
        return 1
      fi
    fi
    if [ -d "${destination_folder}/bats-assert" ]; then
      echo "bats-assert already installed"
    else
      if ! mv "$INSTALL_ONLY_FOLDER/bats-helpers/bats-assert" "${destination_folder}/bats-assert"; then
        echo "error installing bats-assert"
        return 1
      fi
    fi
  fi
  return 0
}

os=$(uname -s)

if ! parse_args "$@"; then
  exit 1
fi

if [ -z "$DOWNLOAD_ONLY_FOLDER" ]; then
  pre_install_report
fi

if ! install_managed_libraries "$os"; then
  echo "error installing package-managed libraries" >&2
  exit 1
fi

if [ -z "$DOWNLOAD_ONLY_FOLDER" ]; then
  if ! response=$(go get -v -t -d ./... 2>&1); then
    printf "error installing go dependencies: %s\n" "$response"
    exit 1
  fi
fi

if [ "$os" == "Linux" ] && ! download_and_install_aws_cli; then
  exit 1
fi

if ! download_and_install_mc "$os"; then
  exit 1
fi

if ! download_and_install_bats_helpers; then
  exit 1
fi

if [ -z "$DOWNLOAD_ONLY_FOLDER" ]; then
  if ! check_required_commands; then
    exit 1
  fi
fi

echo "Install complete"
exit 0
