#!/usr/bin/env pwsh
# Copyright 2026 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# PowerShell equivalent of runtests.sh for Windows

$ErrorActionPreference = "Stop"

# Temp directories
$tmpGw                     = Join-Path $env:TEMP "gw"
$tmpCovdata                = Join-Path $env:TEMP "covdata"
$tmpHttpsCovdata           = Join-Path $env:TEMP "https.covdata"
$tmpVersioningCovdata      = Join-Path $env:TEMP "versioning.covdata"
$tmpVersioningHttpsCovdata = Join-Path $env:TEMP "versioning.https.covdata"
$tmpNoaclCovdata           = Join-Path $env:TEMP "noacl.covdata"
$tmpVersioningDir          = Join-Path $env:TEMP "versioningdir"
$tmpSidecar                = Join-Path $env:TEMP "sidecar"

foreach ($dir in @($tmpGw, $tmpCovdata, $tmpHttpsCovdata, $tmpVersioningCovdata,
                   $tmpVersioningHttpsCovdata, $tmpNoaclCovdata, $tmpVersioningDir,
                   $tmpSidecar)) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    New-Item -ItemType Directory -Path $dir | Out-Null
}

# Setup TLS certificate and key
Write-Host "Generating TLS certificate and key in the cert.pem and key.pem files"
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
if ($LASTEXITCODE -ne 0) { throw "Failed to generate private key" }
openssl req -new -x509 -key key.pem -out cert.pem -days 365 `
    -subj "/C=US/ST=California/L=San Francisco/O=Versity/OU=Software/CN=versity.com"
if ($LASTEXITCODE -ne 0) { throw "Failed to generate certificate" }

function Start-Gateway {
    param(
        [string]   $CoverDir,
        [string[]] $GwArgs
    )
    $env:GOCOVERDIR = $CoverDir
    $proc = Start-Process -FilePath ".\versitygw.exe" -ArgumentList $GwArgs -PassThru -NoNewWindow
    Remove-Item Env:\GOCOVERDIR -ErrorAction SilentlyContinue
    return $proc
}

function Invoke-GwTest {
    param(
        [string]                       $Description,
        [string[]]                     $TestArgs,
        [System.Diagnostics.Process]   $GatewayProc
    )
    & .\versitygw.exe test @TestArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$Description failed"
        Stop-Process -Id $GatewayProc.Id -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 1. HTTP (port 7070)
# ---------------------------------------------------------------------------
Write-Host "Running the sdk test over http"
$gwProc = Start-Gateway -CoverDir $tmpCovdata `
    -GwArgs @("-a", "user", "-s", "pass", "--iam-dir", $tmpGw, "posix", "--sidecar", $tmpSidecar, $tmpGw)
Start-Sleep -Seconds 1

if ($gwProc.HasExited) {
    Write-Host "server no longer running"
    exit 1
}

Invoke-GwTest -Description "full flow tests" -GatewayProc $gwProc `
    -TestArgs @("-a", "user", "-s", "pass", "-e", "http://127.0.0.1:7070", "full-flow", "--parallel", "--windows-test-mode")
Invoke-GwTest -Description "posix tests" -GatewayProc $gwProc `
    -TestArgs @("-a", "user", "-s", "pass", "-e", "http://127.0.0.1:7070", "posix", "--windows-test-mode")
Invoke-GwTest -Description "iam tests" -GatewayProc $gwProc `
    -TestArgs @("-a", "user", "-s", "pass", "-e", "http://127.0.0.1:7070", "gw-iam")

Stop-Process -Id $gwProc.Id -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 2. HTTPS (port 7071)
# ---------------------------------------------------------------------------
Write-Host "Running the sdk test over https"
$gwHttpsProc = Start-Gateway -CoverDir $tmpHttpsCovdata `
    -GwArgs @("--cert", "$PWD\cert.pem", "--key", "$PWD\key.pem",
              "-p", ":7071", "-a", "user", "-s", "pass", "--iam-dir", $tmpGw, "posix", "--sidecar", $tmpSidecar, $tmpGw)
Start-Sleep -Seconds 1

if ($gwHttpsProc.HasExited) {
    Write-Host "https server no longer running"
    exit 1
}

Invoke-GwTest -Description "https full flow tests" -GatewayProc $gwHttpsProc `
    -TestArgs @("--allow-insecure", "-a", "user", "-s", "pass", "-e", "https://127.0.0.1:7071", "full-flow", "--parallel", "--windows-test-mode")
Invoke-GwTest -Description "https posix tests" -GatewayProc $gwHttpsProc `
    -TestArgs @("--allow-insecure", "-a", "user", "-s", "pass", "-e", "https://127.0.0.1:7071", "posix", "--windows-test-mode")
Invoke-GwTest -Description "https iam tests" -GatewayProc $gwHttpsProc `
    -TestArgs @("--allow-insecure", "-a", "user", "-s", "pass", "-e", "https://127.0.0.1:7071", "gw-iam")

Stop-Process -Id $gwHttpsProc.Id -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 3. Versioning HTTP (port 7072)
# ---------------------------------------------------------------------------
Write-Host "Running the sdk test over http against the versioning-enabled gateway"
$gwVsProc = Start-Gateway -CoverDir $tmpVersioningCovdata `
    -GwArgs @("-p", ":7072", "-a", "user", "-s", "pass", "--iam-dir", $tmpGw,
              "posix", "--sidecar", $tmpSidecar, "--versioning-dir", $tmpVersioningDir, $tmpGw)
Start-Sleep -Seconds 1

if ($gwVsProc.HasExited) {
    Write-Host "versioning-enabled server no longer running"
    exit 1
}

Invoke-GwTest -Description "versioning-enabled full-flow tests" -GatewayProc $gwVsProc `
    -TestArgs @("-a", "user", "-s", "pass", "-e", "http://127.0.0.1:7072", "full-flow", "-vs", "--parallel", "--windows-test-mode")
Invoke-GwTest -Description "versioning-enabled posix tests" -GatewayProc $gwVsProc `
    -TestArgs @("-a", "user", "-s", "pass", "-e", "http://127.0.0.1:7072", "posix", "-vs", "--windows-test-mode")

Stop-Process -Id $gwVsProc.Id -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 4. Versioning HTTPS (port 7073)
# ---------------------------------------------------------------------------
Write-Host "Running the sdk test over https against the versioning-enabled gateway"
$gwVsHttpsProc = Start-Gateway -CoverDir $tmpVersioningHttpsCovdata `
    -GwArgs @("--cert", "$PWD\cert.pem", "--key", "$PWD\key.pem",
              "-p", ":7073", "-a", "user", "-s", "pass", "--iam-dir", $tmpGw,
              "posix", "--sidecar", $tmpSidecar, "--versioning-dir", $tmpVersioningDir, $tmpGw)
Start-Sleep -Seconds 1

if ($gwVsHttpsProc.HasExited) {
    Write-Host "versioning-enabled https server no longer running"
    exit 1
}

Invoke-GwTest -Description "versioning-enabled https full-flow tests" -GatewayProc $gwVsHttpsProc `
    -TestArgs @("--allow-insecure", "-a", "user", "-s", "pass", "-e", "https://127.0.0.1:7073", "full-flow", "-vs", "--parallel", "--windows-test-mode")
Invoke-GwTest -Description "versioning-enabled https posix tests" -GatewayProc $gwVsHttpsProc `
    -TestArgs @("--allow-insecure", "-a", "user", "-s", "pass", "-e", "https://127.0.0.1:7073", "posix", "-vs", "--windows-test-mode")

Stop-Process -Id $gwVsHttpsProc.Id -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 5. No ACL (port 7074)
# ---------------------------------------------------------------------------
Write-Host "Running No ACL integration tests"
$gwNoAclProc = Start-Gateway -CoverDir $tmpNoaclCovdata `
    -GwArgs @("-p", ":7074", "-a", "user", "-s", "pass", "-noacl", "--iam-dir", $tmpGw, "posix", "--sidecar", $tmpSidecar, $tmpGw)
Start-Sleep -Seconds 1

if ($gwNoAclProc.HasExited) {
    Write-Host "noacl server no longer running"
    exit 1
}

Invoke-GwTest -Description "No ACL integration tests" -GatewayProc $gwNoAclProc `
    -TestArgs @("--allow-insecure", "-a", "user", "-s", "pass", "-e", "http://127.0.0.1:7074", "noacl")

Stop-Process -Id $gwNoAclProc.Id -Force -ErrorAction SilentlyContinue
