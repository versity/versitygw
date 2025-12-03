# S3 Multi-Backend Configuration Example

**English** | **[Português](README-s3-multi.pt-BR.md)**

This directory contains an example configuration for running VersityGW with multiple S3 backends for fallback support.

## Configuration File: s3-multi-config.json

The configuration file defines multiple S3 backends. The first backend is the primary (used for writes), and subsequent backends are used as fallbacks for read operations.

## Usage

### Basic Usage

```bash
# Gateway credentials will be randomly generated if not provided
versitygw s3-multi --config examples/s3-multi-config.json --port :7070

# Or specify your own gateway credentials
versitygw s3-multi \
  --config examples/s3-multi-config.json \
  --access ROOT_ACCESS_KEY \
  --secret ROOT_SECRET_KEY \
  --port :7070
```

**Note:** If you don't provide `--access` and `--secret`, VersityGW will automatically generate random credentials and display them on startup. These are the credentials S3 clients will use to connect to the gateway (not to be confused with the backend credentials in the config file).

### With Environment Variables

You can override configuration values using environment variables:

```bash
export VGW_S3_MULTI_BACKEND_0_ACCESS="primary_key"
export VGW_S3_MULTI_BACKEND_0_SECRET="primary_secret"
export VGW_S3_MULTI_BACKEND_0_ENDPOINT="https://s3.amazonaws.com"
export VGW_S3_MULTI_BACKEND_1_ACCESS="fallback_key"
export VGW_S3_MULTI_BACKEND_1_SECRET="fallback_secret"
export VGW_S3_MULTI_BACKEND_1_ENDPOINT="https://backup-s3.example.com"

# Gateway credentials can be set via env vars or auto-generated
export ROOT_ACCESS_KEY="my-gateway-key"  # Optional
export ROOT_SECRET_KEY="my-gateway-secret"  # Optional

versitygw s3-multi --config examples/s3-multi-config.json --port :7070
```

### With Debug Mode

```bash
versitygw s3-multi \
  --config examples/s3-multi-config.json \
  --access ROOT_ACCESS_KEY \
  --secret ROOT_SECRET_KEY \
  --port :7070 \
  --debug
```

## How It Works

### Read Operations (GET, HEAD, LIST)
When a client requests an object:
1. VersityGW first tries the primary backend
2. If the object is not found (404), it automatically tries the next backend
3. This continues until the object is found or all backends have been tried
4. If no backend has the object, a 404 is returned to the client

### Write Operations (PUT, DELETE)
All write operations go to the primary (first) backend only:
- Object uploads (PUT)
- Object deletions (DELETE)
- Bucket creation/deletion
- ACL/policy modifications
- Tagging operations

### Presigned URLs

Presigned URLs work seamlessly with multi-backend fallback. The gateway re-signs requests for each backend automatically.

**How Expiration Works:**
- Expiration time is set by the **CLIENT** when generating the URL (not by the gateway)
- The client specifies `--expires-in <seconds>` when creating the presigned URL
- Gateway validates that expiration is within limits: 1 second to 7 days (604800 seconds)
- Default AWS CLI expiration: 1 hour (3600 seconds) if not specified

**Setting Expiration Time:**

```bash
# Generate URL with 5 minutes expiration
aws s3 presign s3://mybucket/file.txt \
  --expires-in 300 \
  --endpoint-url http://localhost:7070

# Generate URL with 24 hours expiration
aws s3 presign s3://mybucket/file.txt \
  --expires-in 86400 \
  --endpoint-url http://localhost:7070

# Generate URL with maximum expiration (7 days)
aws s3 presign s3://mybucket/file.txt \
  --expires-in 604800 \
  --endpoint-url http://localhost:7070
```

**Common Expiration Times:**
- 5 minutes: `--expires-in 300`
- 30 minutes: `--expires-in 1800`
- 1 hour: `--expires-in 3600` (default)
- 24 hours: `--expires-in 86400`
- 7 days: `--expires-in 604800` (maximum)

**Multi-Backend Behavior:**
- Presigned URLs try each backend until the object is found
- Expiration is validated for each backend attempt
- Once expired, URL is rejected on ALL backends

## Configuration Options

### Gateway Credentials (Random Generation)

VersityGW can automatically generate random credentials for the gateway itself:

- If you **don't provide** `--access` and `--secret` (or `ROOT_ACCESS_KEY` and `ROOT_SECRET_KEY` env vars), VersityGW will generate cryptographically secure random credentials on startup
- The generated credentials will be displayed in the console output
- These are the credentials S3 clients use to connect to the gateway (separate from backend credentials)

Example output:
```
⚠️  Generated random ACCESS KEY: k8jN2mP9xQwE4rTyU5iO
⚠️  Generated random SECRET KEY: vL7sD3fG6hJ9kM2nB5vC8xZ1aS4dF7gH9jK2lM5n
```

### Backend Configuration Fields

Each backend in the `backends` array supports these fields:

- **name** (string): Human-readable name for logging/debugging
- **access** (string, required): AWS access key ID for this backend
- **secret** (string, required): AWS secret access key for this backend
- **endpoint** (string): S3 endpoint URL (defaults to AWS if empty)
- **region** (string): AWS region (defaults to "us-east-1")
- **metaBucket** (string): Meta bucket for storing ACLs/policies
- **disableChecksum** (bool): Disable checksum validation
- **sslSkipVerify** (bool): Skip SSL certificate verification
- **usePathStyle** (bool): Use path-style addressing instead of virtual-host style

## Example Scenarios

### Scenario 1: Cloudflare R2 Dual Bucket (Recommended)

Perfect for cost-effective multi-backend setup with Cloudflare R2:

```json
{
  "backends": [
    {
      "name": "r2-primary-bucket",
      "access": "YOUR_R2_ACCESS_KEY_ID",
      "secret": "YOUR_R2_SECRET_ACCESS_KEY",
      "endpoint": "https://YOUR_ACCOUNT_ID.r2.cloudflarestorage.com/primary-bucket",
      "region": "us-east-1"
    },
    {
      "name": "r2-fallback-bucket",
      "access": "YOUR_R2_ACCESS_KEY_ID",
      "secret": "YOUR_R2_SECRET_ACCESS_KEY",
      "endpoint": "https://YOUR_ACCOUNT_ID.r2.cloudflarestorage.com/fallback-bucket",
      "region": "us-east-1"
    }
  ]
}
```

**Important:** For Cloudflare R2, use `"region": "us-east-1"` in the backend config. AWS CLI must also use `us-east-1` as the region (`export AWS_DEFAULT_REGION=us-east-1` or `aws configure set region us-east-1`).

**Run with random gateway credentials:**
```bash
versitygw s3-multi --config r2-config.json --port :7070
# Gateway will auto-generate and display ACCESS/SECRET keys
```

See `examples/s3-multi-cloudflare-r2.json` for a complete template.

### Scenario 2: AWS S3 with On-Premises Backup
```json
{
  "backends": [
    {
      "name": "aws-s3-primary",
      "access": "AWS_KEY",
      "secret": "AWS_SECRET",
      "endpoint": "",
      "region": "us-east-1"
    },
    {
      "name": "local-minio",
      "access": "MINIO_KEY",
      "secret": "MINIO_SECRET",
      "endpoint": "https://minio.local:9000",
      "region": "us-east-1",
      "usePathStyle": true
    }
  ]
}
```

### Scenario 3: Multi-Region Fallback
```json
{
  "backends": [
    {
      "name": "us-east",
      "access": "KEY1",
      "secret": "SECRET1",
      "endpoint": "https://s3.us-east-1.amazonaws.com",
      "region": "us-east-1"
    },
    {
      "name": "eu-west",
      "access": "KEY2",
      "secret": "SECRET2",
      "endpoint": "https://s3.eu-west-1.amazonaws.com",
      "region": "eu-west-1"
    }
  ]
}
```

### Scenario 4: Three-Tier Fallback
```json
{
  "backends": [
    {
      "name": "hot-storage",
      "access": "HOT_KEY",
      "secret": "HOT_SECRET",
      "endpoint": "https://fast-s3.example.com",
      "region": "us-east-1"
    },
    {
      "name": "warm-storage",
      "access": "WARM_KEY",
      "secret": "WARM_SECRET",
      "endpoint": "https://s3.example.com",
      "region": "us-east-1"
    },
    {
      "name": "cold-storage",
      "access": "COLD_KEY",
      "secret": "COLD_SECRET",
      "endpoint": "https://glacier-s3.example.com",
      "region": "us-east-1"
    }
  ]
}
```

## Testing

### Test Fallback Behavior

1. Start VersityGW with multi-backend configuration
2. Upload a file (goes to primary backend only):
   ```bash
   aws s3 cp test.txt s3://mybucket/test.txt --endpoint-url http://localhost:7070
   ```

3. The file is now only in the primary backend

4. Try to read the file (should succeed from primary):
   ```bash
   aws s3 cp s3://mybucket/test.txt downloaded.txt --endpoint-url http://localhost:7070
   ```

5. To test fallback, manually upload a file to the secondary backend outside of VersityGW, then try to read it through VersityGW - it should find it in the fallback backend

## Limitations

- Multipart uploads are only supported on the primary backend
- Object versioning queries only the primary backend
- Bucket listing combines results from all backends (may show duplicate bucket names)
- No automatic synchronization between backends
- Write operations don't replicate to fallback backends
