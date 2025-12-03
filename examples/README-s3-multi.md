# S3 Multi-Backend Configuration Example

This directory contains an example configuration for running VersityGW with multiple S3 backends for fallback support.

## Configuration File: s3-multi-config.json

The configuration file defines multiple S3 backends. The first backend is the primary (used for writes), and subsequent backends are used as fallbacks for read operations.

## Usage

### Basic Usage

```bash
versitygw s3-multi \
  --config examples/s3-multi-config.json \
  --access ROOT_ACCESS_KEY \
  --secret ROOT_SECRET_KEY \
  --port :7070
```

### With Environment Variables

You can override configuration values using environment variables:

```bash
export VGW_S3_MULTI_BACKEND_0_ACCESS="primary_key"
export VGW_S3_MULTI_BACKEND_0_SECRET="primary_secret"
export VGW_S3_MULTI_BACKEND_0_ENDPOINT="https://s3.amazonaws.com"
export VGW_S3_MULTI_BACKEND_1_ACCESS="fallback_key"
export VGW_S3_MULTI_BACKEND_1_SECRET="fallback_secret"
export VGW_S3_MULTI_BACKEND_1_ENDPOINT="https://backup-s3.example.com"

versitygw s3-multi \
  --config examples/s3-multi-config.json \
  --access ROOT_ACCESS_KEY \
  --secret ROOT_SECRET_KEY \
  --port :7070
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
Presigned URLs work as expected with the standard expiration handling:
- URLs are validated with `X-Amz-Expires` parameter
- Maximum expiration: 7 days (604800 seconds)
- Expired URLs return `ErrExpiredPresignRequest`

## Configuration Options

Each backend in the `backends` array supports these fields:

- **name** (string): Human-readable name for logging/debugging
- **access** (string, required): AWS access key ID
- **secret** (string, required): AWS secret access key
- **endpoint** (string): S3 endpoint URL (defaults to AWS if empty)
- **region** (string): AWS region (defaults to "us-east-1")
- **metaBucket** (string): Meta bucket for storing ACLs/policies
- **disableChecksum** (bool): Disable checksum validation
- **sslSkipVerify** (bool): Skip SSL certificate verification
- **usePathStyle** (bool): Use path-style addressing instead of virtual-host style

## Example Scenarios

### Scenario 1: AWS S3 with On-Premises Backup
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

### Scenario 2: Multi-Region Fallback
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

### Scenario 3: Three-Tier Fallback
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
