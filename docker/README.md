# VersityGW Multi-Backend Docker Setup

Complete Docker Compose setup for running VersityGW in multi-backend mode with automatic fallback.

## Features

- 🐳 **Docker Compose** - Easy deployment with single command
- ⚙️ **Environment Variables** - Configure everything via `.env` file
- 🔐 **Auto-Generated Credentials** - Optional random gateway credentials
- 📝 **Multiple Config Examples** - AWS S3, Cloudflare R2, Multi-provider
- 🔄 **Auto-Restart** - Container restarts automatically on failure
- 💚 **Health Checks** - Built-in container health monitoring
- 📊 **Resource Limits** - Optional CPU and memory constraints

## Quick Start

### 1. Copy Environment File

```bash
cd docker
cp .env.example .env
```

### 2. Create Configuration File

Choose one of the config examples:

```bash
# For AWS S3
cp configs/config.example.json configs/config.json

# For Cloudflare R2
cp configs/cloudflare-r2.example.json configs/config.json

# For Multi-Provider
cp configs/multi-provider.example.json configs/config.json
```

Edit `configs/config.json` with your backend credentials.

### 3. Configure Environment (Optional)

Edit `.env` file to customize:

```bash
# Server port
VGW_PORT=7070

# Gateway credentials (leave empty for auto-generation)
VGW_ACCESS_KEY=
VGW_SECRET_KEY=

# Config file path
CONFIG_PATH=./configs/config.json

# Debug mode
VGW_DEBUG=false
```

### 4. Start the Gateway

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### 5. Test the Gateway

```bash
# Configure AWS CLI
export AWS_ACCESS_KEY_ID=<gateway-access-key>
export AWS_SECRET_ACCESS_KEY=<gateway-secret-key>
export AWS_ENDPOINT_URL=http://localhost:7070
export AWS_DEFAULT_REGION=us-east-1

# Test operations
aws s3 ls
aws s3 cp test.txt s3://my-bucket/
aws s3 ls s3://my-bucket/

# Generate presigned URL (default 1 hour expiration)
aws s3 presign s3://my-bucket/test.txt

# Generate presigned URL with custom expiration (5 minutes)
aws s3 presign s3://my-bucket/test.txt --expires-in 300
```

## Presigned URLs

### Setting Expiration Time

The expiration time for presigned URLs is set by the **CLIENT** when generating the URL, not by the gateway.

**Common expiration times:**
```bash
# 5 minutes
aws s3 presign s3://bucket/file.txt --expires-in 300

# 1 hour (default)
aws s3 presign s3://bucket/file.txt --expires-in 3600

# 24 hours
aws s3 presign s3://bucket/file.txt --expires-in 86400

# Maximum (7 days)
aws s3 presign s3://bucket/file.txt --expires-in 604800
```

**Limits validated by gateway:**
- Minimum: 1 second
- Maximum: 7 days (604800 seconds)
- Default: 1 hour (3600 seconds) if not specified

**No gateway configuration needed** - the client controls expiration time via `--expires-in` parameter.

## Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `VGW_CONFIG_FILE` | Path to config JSON inside container | `/etc/versitygw/config.json` | Yes (auto) |
| `VGW_ACCESS_KEY` | Gateway access key for clients | (auto-generated) | No |
| `VGW_SECRET_KEY` | Gateway secret key for clients | (auto-generated) | No |
| `VGW_PORT` | Server port | `7070` | No |
| `VGW_HOST` | Server host/address | `0.0.0.0` | No |
| `VGW_REGION` | Gateway region | `us-east-1` | No |
| `VGW_DEBUG` | Enable debug logging | `false` | No |
| `CONFIG_PATH` | Host path to config file | `./configs/config.json` | Yes |

### Backend Configuration File

The JSON configuration file defines your S3 backends:

```json
{
  "backends": [
    {
      "name": "primary-backend",
      "access": "BACKEND_ACCESS_KEY",
      "secret": "BACKEND_SECRET_KEY",
      "endpoint": "https://s3.provider.com/bucket-name",
      "region": "us-east-1"
    },
    {
      "name": "fallback-backend",
      "access": "BACKEND_ACCESS_KEY",
      "secret": "BACKEND_SECRET_KEY",
      "endpoint": "https://s3.provider.com/fallback-bucket",
      "region": "us-east-1"
    }
  ]
}
```

**Important Notes:**
- **Endpoint format**: Must include bucket name in path (e.g., `https://endpoint.com/bucket-name`)
- **Cloudflare R2**: Always use `"region": "us-east-1"`, not `"auto"`
- **Credentials**: These are for accessing the backend storage, NOT for clients connecting to the gateway

## Usage Examples

### Example 1: Auto-Generated Gateway Credentials

```bash
# Don't set VGW_ACCESS_KEY and VGW_SECRET_KEY in .env
docker-compose up -d

# Check logs for generated credentials
docker-compose logs | grep "Generated random"
# Output:
# ⚠️  Generated random ACCESS KEY: HLhzp7dJ6pOpKSzWfzoy
# ⚠️  Generated random SECRET KEY: jVde2GVT-wnZK1mc1FHX-2JCCJTtkXetnvAda-Kg
```

### Example 2: Custom Gateway Credentials

Edit `.env`:
```bash
VGW_ACCESS_KEY=my-custom-access-key
VGW_SECRET_KEY=my-custom-secret-key
```

```bash
docker-compose up -d
```

### Example 3: HTTPS/TLS Support

Create certificates:
```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key -out certs/server.crt
```

Edit `.env`:
```bash
VGW_CERT=/etc/versitygw/certs/server.crt
VGW_KEY=/etc/versitygw/certs/server.key
```

Uncomment volume in `docker-compose.yml`:
```yaml
volumes:
  - ./certs:/etc/versitygw/certs:ro
```

```bash
docker-compose up -d
```

### Example 4: Debug Mode

Edit `.env`:
```bash
VGW_DEBUG=true
```

```bash
docker-compose up -d
docker-compose logs -f  # Watch detailed logs
```

### Example 5: Different Port

Edit `.env`:
```bash
VGW_PORT=8080
```

```bash
docker-compose up -d
# Gateway now available at http://localhost:8080
```

## Configuration Examples

### Cloudflare R2 Dual-Bucket Setup

`configs/config.json`:
```json
{
  "backends": [
    {
      "name": "r2-primary",
      "access": "abc123...",
      "secret": "xyz789...",
      "endpoint": "https://abc123.r2.cloudflarestorage.com/primary-bucket",
      "region": "us-east-1"
    },
    {
      "name": "r2-fallback",
      "access": "abc123...",
      "secret": "xyz789...",
      "endpoint": "https://abc123.r2.cloudflarestorage.com/fallback-bucket",
      "region": "us-east-1"
    }
  ]
}
```

### AWS S3 Multi-Region Setup

`configs/config.json`:
```json
{
  "backends": [
    {
      "name": "s3-us-east",
      "access": "AWS_ACCESS_KEY",
      "secret": "AWS_SECRET_KEY",
      "endpoint": "https://s3.us-east-1.amazonaws.com/my-bucket-east",
      "region": "us-east-1"
    },
    {
      "name": "s3-eu-west",
      "access": "AWS_ACCESS_KEY",
      "secret": "AWS_SECRET_KEY",
      "endpoint": "https://s3.eu-west-1.amazonaws.com/my-bucket-eu",
      "region": "eu-west-1"
    }
  ]
}
```

### Hybrid Multi-Provider Setup

`configs/config.json`:
```json
{
  "backends": [
    {
      "name": "aws-primary",
      "access": "AWS_ACCESS_KEY",
      "secret": "AWS_SECRET_KEY",
      "endpoint": "https://s3.us-east-1.amazonaws.com/prod-bucket",
      "region": "us-east-1"
    },
    {
      "name": "r2-backup",
      "access": "R2_ACCESS_KEY",
      "secret": "R2_SECRET_KEY",
      "endpoint": "https://account.r2.cloudflarestorage.com/backup-bucket",
      "region": "us-east-1"
    },
    {
      "name": "minio-local",
      "access": "MINIO_ACCESS_KEY",
      "secret": "MINIO_SECRET_KEY",
      "endpoint": "https://minio.internal.company.com/archive-bucket",
      "region": "us-east-1"
    }
  ]
}
```

## Docker Commands

### Basic Operations

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# View logs
docker-compose logs -f

# View logs for last 100 lines
docker-compose logs --tail=100

# Check status
docker-compose ps

# Execute command inside container
docker-compose exec versitygw-multibackend sh
```

### Rebuild Image

```bash
# Rebuild after code changes
docker-compose build

# Force rebuild without cache
docker-compose build --no-cache

# Rebuild and restart
docker-compose up -d --build
```

### Resource Management

```bash
# View resource usage
docker stats versitygw-multibackend

# View container details
docker inspect versitygw-multibackend

# Remove everything (including volumes)
docker-compose down -v
```

## Troubleshooting

### Problem: Container keeps restarting

Check logs:
```bash
docker-compose logs versitygw-multibackend
```

Common causes:
- Invalid config file path
- Missing backend credentials
- Malformed JSON in config file
- Port already in use

### Problem: Cannot connect to backend

Enable debug mode:
```bash
# Edit .env
VGW_DEBUG=true

# Restart
docker-compose restart
docker-compose logs -f
```

### Problem: Health check failing

Test manually:
```bash
curl http://localhost:7070/
# or
docker-compose exec versitygw-multibackend wget -O- http://localhost:7070/
```

### Problem: Config file not found

Verify volume mount:
```bash
docker-compose exec versitygw-multibackend cat /etc/versitygw/config.json
```

## Security Best Practices

1. **Never commit credentials** - Use `.env` file (already in `.gitignore`)
2. **Use HTTPS/TLS** in production - Mount certificates and configure `VGW_CERT`/`VGW_KEY`
3. **Rotate credentials** regularly - Both gateway and backend credentials
4. **Limit container resources** - Uncomment `deploy.resources` in `docker-compose.yml`
5. **Use secrets management** - Consider Docker secrets or external vaults for production

## Production Deployment

For production, consider:

1. **Use Docker Secrets**:
```yaml
secrets:
  gateway_access_key:
    file: ./secrets/gateway_access_key.txt
  gateway_secret_key:
    file: ./secrets/gateway_secret_key.txt
```

2. **Enable Resource Limits**:
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
```

3. **Use External Configuration**:
```yaml
configs:
  backend_config:
    file: ./configs/config.json
```

4. **Set Up Monitoring**:
- Add Prometheus metrics export
- Configure log aggregation
- Set up alerting

5. **Use Reverse Proxy**:
- Nginx or Traefik in front
- Handle TLS termination
- Rate limiting and caching

## Additional Resources

- [Main Documentation](../README.md)
- [Multi-Backend Guide](../examples/README-s3-multi.md)
- [Portuguese Documentation](../README.pt-BR.md)
- [Configuration Examples](./configs/)

## Support

For issues or questions:
- GitHub Issues: https://github.com/versity/versitygw/issues
- Fork Repository: https://github.com/klaoslacerdacs/versitygw-multibackend
