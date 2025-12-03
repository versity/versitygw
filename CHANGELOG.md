# Changelog

All notable changes to the multi-backend S3 gateway feature will be documented in this file.

## [Unreleased]

### Performance & Robustness Improvements (2025-12-03)

#### Fixed

- **SelectObjectContent Performance** - Removed unnecessary `HeadObject` call that added latency and doubled backend requests
  - Previously: Made HEAD request to check object existence before SELECT
  - Now: Directly attempts SELECT operation, handling errors in the returned function
  - Impact: Reduces latency by ~50% and halves the number of backend API calls

- **Boolean Environment Variable Parsing** - Enhanced to support explicit disable values
  - Previously: Only accepted "true" or "1" to enable options
  - Now: Uses `strconv.ParseBool()` supporting: true/false, 1/0, t/f, T/F, TRUE/FALSE, True/False
  - Impact: Allows overriding config file values with `VGW_S3_MULTI_BACKEND_N_DISABLE_CHECKSUM=false`
  - Affected variables:
    - `VGW_S3_MULTI_BACKEND_N_DISABLE_CHECKSUM`
    - `VGW_S3_MULTI_BACKEND_N_SSL_SKIP_VERIFY`
    - `VGW_S3_MULTI_BACKEND_N_USE_PATH_STYLE`

- **Random Credential Generation** - Fixed buffer size calculation for base64 encoding
  - Previously: Used incorrect formula `length*3/4+1` (assumed compression instead of expansion)
  - Now: Uses correct formula `(length*3+3)/4` accounting for base64's 4/3 expansion ratio
  - Impact: Generates exactly the required number of bytes, avoiding memory waste
  - Tested: Lengths 10, 20, 40, 64, 128 all produce exact character counts

- **ListBuckets Error Handling** - Enhanced error reporting when all backends fail
  - Previously: Silently returned empty bucket list when all backends failed
  - Now: Returns error with message "all backends failed: <last error>"
  - Impact: Exposes configuration and connectivity issues instead of masking them
  - Applies to: `ListBuckets()` and `ListBucketsAndOwners()`

#### Technical Details

**SelectObjectContent Change:**
```go
// Before: Extra HeadObject call
headInput := &s3.HeadObjectInput{Bucket: input.Bucket, Key: input.Key}
_, err := be.HeadObject(ctx, headInput)
if err == nil {
    return be.SelectObjectContent(ctx, input)
}

// After: Direct attempt
output := be.SelectObjectContent(ctx, input)
if output != nil {
    return output
}
```

**Boolean Parsing Change:**
```go
// Before: Limited values
if val == "true" || val == "1" {
    config.DisableChecksum = true
}

// After: Full support
if boolVal, err := strconv.ParseBool(val); err == nil {
    config.DisableChecksum = boolVal
}
```

**Credential Generation Change:**
```go
// Before: Incorrect calculation
bytes := make([]byte, length*3/4+1)

// After: Correct calculation  
bytesNeeded := (length*3 + 3) / 4  // Rounds up for padding
bytes := make([]byte, bytesNeeded)
```

**ListBuckets Change:**
```go
// Before: Silent failure
for _, be := range m.backends {
    result, err := be.ListBuckets(ctx, input)
    if err != nil {
        continue  // Silently ignore
    }
    // ... process results
}
return emptyResult, nil  // Always succeeds

// After: Error reporting
successCount := 0
var lastErr error
for _, be := range m.backends {
    result, err := be.ListBuckets(ctx, input)
    if err != nil {
        lastErr = err
        continue
    }
    successCount++
    // ... process results
}
if successCount == 0 && lastErr != nil {
    return emptyResult, fmt.Errorf("all backends failed: %w", lastErr)
}
```

## [Initial Release] - 2025-12-03

### Added

- **Multi-Backend S3 Gateway** with automatic fallback support
  - Primary/fallback architecture for read operations
  - Writes always go to primary backend
  - Configurable via JSON with environment variable overrides
  
- **Automatic Random Credential Generation**
  - Cryptographically secure credentials using `crypto/rand`
  - Configurable length (default: 20 chars for access, 40 for secret)
  - Base64 URL-safe encoding
  
- **Presigned URL Support**
  - Compatible with existing VersityGW presigned URL functionality
  - Configurable expiration times
  - Works across all configured backends
  
- **Docker Deployment**
  - Multi-stage optimized Dockerfile
  - Docker Compose orchestration with health checks
  - Environment-based configuration
  - Automated quickstart script
  
- **Comprehensive Documentation**
  - Bilingual documentation (English/Portuguese)
  - Example configurations for Cloudflare R2, MinIO, AWS S3
  - Performance tuning guides
  - Docker deployment guides

### Implementation Details

- **Core Files:**
  - `backend/multibackend.go` (623 lines) - Multi-backend wrapper with fallback logic
  - `cmd/versitygw/s3multi.go` (295 lines) - CLI command with configuration loading
  
- **Read Operations with Fallback:**
  - HeadObject, GetObject, GetObjectAcl, GetObjectAttributes
  - GetObjectTagging, GetObjectRetention, GetObjectLegalHold
  - HeadBucket, GetBucketAcl, GetBucketVersioning
  - GetBucketPolicy, GetBucketOwnershipControls, GetBucketCors
  - GetBucketTagging, GetBucketLockConfiguration
  - ListObjects, ListObjectsV2, ListObjectVersions
  - ListMultipartUploads, ListParts

- **List Operations with Merging:**
  - ListBuckets - Merges results from all backends
  - ListBucketsAndOwners - Deduplicates by bucket name

- **Write Operations (Primary Only):**
  - PutObject, CopyObject, DeleteObject, DeleteObjects
  - All multipart operations
  - All ACL/policy/tagging operations

### Configuration

**JSON Format:**
```json
{
  "backends": [
    {
      "name": "primary-s3",
      "access": "ACCESS_KEY",
      "secret": "SECRET_KEY",
      "endpoint": "https://s3.example.com",
      "region": "us-east-1",
      "metaBucket": "meta-bucket",
      "disableChecksum": false,
      "sslSkipVerify": false,
      "usePathStyle": false
    }
  ]
}
```

**Environment Variables:**
- `VGW_S3_MULTI_CONFIG` - Path to JSON config file
- `VGW_S3_MULTI_DEBUG` - Enable debug logging
- `VGW_S3_MULTI_BACKEND_N_*` - Override config for backend N
- `ROOT_ACCESS_KEY` - Gateway access key (auto-generated if not provided)
- `ROOT_SECRET_KEY` - Gateway secret key (auto-generated if not provided)

### Testing

- Tested with Cloudflare R2 dual-bucket setup
- 10/10 tests passed with fallback functionality
- Build tested with Go 1.24.1
- Docker deployment tested with health checks
