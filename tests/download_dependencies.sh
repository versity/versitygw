#!/usr/bin/env bash

download_apt_packages() {
  if [ $# -lt 1 ]; then
    echo "download_apt_packages requires download folder, packages" >&2
    return 1
  fi
  local download_folder
  download_folder="$(realpath -m "$1")/apt" packages=("${@:2}")

  if ! mkdir -p "$download_folder"; then
    echo "error creating apt download folder" >&2
    return 1
  fi

  if ! env DEBIAN_FRONTEND=noninteractive sudo apt-get update; then
    echo "error with apt update" >&2
    return 1
  fi

  if ! env DEBIAN_FRONTEND=noninteractive sudo apt-get install --download-only --reinstall -y -o "Dir::Cache::archives=$download_folder" "${packages[@]}"; then
    echo "error with apt download" >&2
    return 1
  else
    echo "download successful"
  fi
  if ! sudo rm -rf "${download_folder}/partial" "${download_folder}/lock"; then
    echo "error removing apt-specific repo files and folders"
    return 1
  fi
  return 0
}

download_aws() {
  if [ $# -gt 1 ]; then
    echo "download_aws should only have optional download folder" >&2
    return 1
  fi
  local download_folder="$1"
  local aws_folder response archive_name download_path

  if [ -n "$download_folder" ]; then
    aws_folder="$1/aws"
    if ! response=$(mkdir -p "$aws_folder" 2>&1); then
      echo "error making download path: $response" >&2
      return 1
    fi
  else
    aws_folder="$(mktemp -d)" || return 1
  fi

  archive_name="$AWS_ARCHIVE_NAME"
  download_path="${aws_folder}/${archive_name}"

  case "$(uname -m)" in
    x86_64|amd64)
      download_url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
      ;;
    aarch64|arm64)
      download_url="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"
      ;;
    *)
      echo "error: unsupported Linux architecture for AWS CLI: $(uname -m)" >&2
      rm -rf "$aws_folder"
      return 1
      ;;
  esac
  if ! curl -fsSL "$download_url" -o "$download_path"; then
    echo "error: failed to download AWS CLI" >&2
    rm -rf "$aws_folder"
    return 1
  fi
  printf '%s\n' "$download_path"
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

download_mc() {
  if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "download_mc requires os, optional download folder" >&2
    return 1
  fi
  local os="$1" download_folder="$2"

  if ! response=$(get_mc_download_link "$os" 2>&1); then
    echo "error getting mc download link: $response" >&2
    return 1
  fi
  download_url="$response"

  if [ -n "$download_folder" ]; then
    mc_folder="$download_folder/mc"
    if ! response=$(mkdir -p "$mc_folder" 2>&1); then
      echo "error making download path: $response" >&2
      return 1
    fi
  else
    mc_folder="$(mktemp -d)" || return 1
  fi
  download_path="${mc_folder}/mc"

  if ! curl -fsSL "$download_url" -o "$download_path"; then
    echo "error: failed to download mc" >&2
    rm -rf "$mc_folder"
    return 1
  fi

  if ! chmod 755 "$download_path"; then
    echo "error: failed to mark mc executable" >&2
    rm -rf "$mc_folder"
    return 1
  fi
  printf '%s\n' "$download_path"
  return 0
}

download_bats_helpers() {
  if [ $# -ne 1 ]; then
    echo "download_bats_helpers requires destination folder" >&2
    return 1
  fi
  local destination_folder="$1"

  if ! mkdir -p "$destination_folder"; then
    echo "error making folder $destination_folder" >&2
    return 1
  fi
  if [ -d "${destination_folder}/bats-support" ]; then
    echo "bats-support already installed"
  else
    if ! git clone https://github.com/bats-core/bats-support.git "${destination_folder}/bats-support"; then
      echo "error getting bats-support library" >&2
      return 1
    fi
  fi
  if [ -d "${destination_folder}/bats-assert" ]; then
    echo "bats-assert already installed"
  else
    if ! git clone https://github.com/ztombol/bats-assert.git "${destination_folder}/bats-assert"; then
      echo "error getting bats-assert library" >&2
      return 1
    fi
  fi
  return 0
}
