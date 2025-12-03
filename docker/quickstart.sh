#!/bin/bash
set -e

# VersityGW Multi-Backend Docker - Quick Start Script
# This script helps you quickly set up and run VersityGW in Docker

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================================"
echo "VersityGW Multi-Backend Docker - Quick Start"
echo "================================================"
echo ""

# Check if docker and docker-compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: Docker Compose is not installed"
    echo "Please install Docker Compose first: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "📝 Creating .env file from example..."
    cp .env.example .env
    echo "✅ .env file created"
    echo ""
fi

# Check if config.json exists
if [ ! -f configs/config.json ]; then
    echo "⚠️  No config.json found!"
    echo ""
    echo "Available configuration examples:"
    echo "  1. Generic S3 config (configs/config.example.json)"
    echo "  2. Cloudflare R2 config (configs/cloudflare-r2.example.json)"
    echo "  3. Multi-provider config (configs/multi-provider.example.json)"
    echo ""
    read -p "Which config would you like to use? [1/2/3]: " config_choice
    
    case $config_choice in
        1)
            echo "📝 Copying generic S3 config..."
            cp configs/config.example.json configs/config.json
            ;;
        2)
            echo "📝 Copying Cloudflare R2 config..."
            cp configs/cloudflare-r2.example.json configs/config.json
            ;;
        3)
            echo "📝 Copying multi-provider config..."
            cp configs/multi-provider.example.json configs/config.json
            ;;
        *)
            echo "❌ Invalid choice. Using generic S3 config..."
            cp configs/config.example.json configs/config.json
            ;;
    esac
    
    echo "✅ Config file created"
    echo ""
    echo "⚠️  IMPORTANT: Edit configs/config.json with your backend credentials!"
    echo ""
    read -p "Press Enter to continue after editing the config file..."
fi

# Ask about gateway credentials
echo ""
echo "Gateway Credentials Setup"
echo "-------------------------"
echo "Do you want to:"
echo "  1. Auto-generate random credentials (recommended for testing)"
echo "  2. Set custom credentials"
echo ""
read -p "Choose option [1/2]: " cred_choice

if [ "$cred_choice" = "2" ]; then
    echo ""
    read -p "Enter ACCESS KEY: " access_key
    # Use -s flag to hide secret key input
    read -sp "Enter SECRET KEY: " secret_key
    echo ""
    
    # Update .env file
    sed -i.bak "s|^VGW_ACCESS_KEY=.*|VGW_ACCESS_KEY=$access_key|g" .env
    sed -i.bak "s|^VGW_SECRET_KEY=.*|VGW_SECRET_KEY=$secret_key|g" .env
    rm -f .env.bak
    
    echo "✅ Custom credentials configured"
else
    echo "✅ Will use auto-generated credentials"
    echo "⚠️  Credentials will be shown ONCE in the startup output below"
    echo "    Make sure to save them securely!"
fi

# Ask about port
echo ""
read -p "Which port should the gateway use? [default: 7070]: " port
if [ -n "$port" ]; then
    sed -i.bak "s|^VGW_PORT=.*|VGW_PORT=$port|g" .env
    rm -f .env.bak
    echo "✅ Port set to $port"
else
    port=7070
    echo "✅ Using default port 7070"
fi

# Ask about debug mode
echo ""
read -p "Enable debug mode? [y/N]: " debug_choice
if [ "$debug_choice" = "y" ] || [ "$debug_choice" = "Y" ]; then
    sed -i.bak "s|^VGW_DEBUG=.*|VGW_DEBUG=true|g" .env
    rm -f .env.bak
    echo "✅ Debug mode enabled"
fi

# Build and start
echo ""
echo "🔨 Building Docker image..."
docker-compose build

echo ""
echo "🚀 Starting VersityGW Multi-Backend..."
docker-compose up -d

echo ""
echo "⏳ Waiting for service to be ready..."
sleep 3

# Check if container is running
if docker-compose ps | grep -q "Up"; then
    echo "✅ VersityGW is running!"
    echo ""
    
    # Show credentials if auto-generated
    # Note: Credentials are only displayed once during startup for security
    if [ "$cred_choice" != "2" ]; then
        echo "🔐 Credentials were auto-generated for this session."
        echo "================================"
        echo "⚠️  For security, auto-generated credentials are not displayed in logs."
        echo "   To use your own credentials and avoid logging secrets, set"
        echo "   VGW_ACCESS_KEY and VGW_SECRET_KEY in a .env file before running this script."
        echo ""
        echo "💡 TIP: See the .env.example file for guidance."
        echo ""
        
        
    fi
    
    echo "📊 Service Information:"
    echo "================================"
    echo "Gateway URL: http://localhost:$port"
    echo ""
    
    echo "📝 View Logs:"
    echo "  docker-compose logs -f"
    echo ""
    
    echo "🛑 Stop Service:"
    echo "  docker-compose down"
    echo ""
    
    echo "🔄 Restart Service:"
    echo "  docker-compose restart"
    echo ""
    
    echo "🧪 Test with AWS CLI:"
    echo "  export AWS_ENDPOINT_URL=http://localhost:$port"
    echo "  export AWS_DEFAULT_REGION=us-east-1"
    if [ "$cred_choice" = "2" ]; then
        echo "  export AWS_ACCESS_KEY_ID=$access_key"
        echo "  export AWS_SECRET_ACCESS_KEY=$secret_key"
    else
        echo "  export AWS_ACCESS_KEY_ID=<check logs for generated key>"
        echo "  export AWS_SECRET_ACCESS_KEY=<check logs for generated key>"
    fi
    echo "  aws s3 ls"
    echo ""
    
    echo "================================================"
    echo "✅ Setup Complete!"
    echo "================================================"
else
    echo "❌ Error: Container failed to start"
    echo ""
    echo "Check logs with:"
    echo "  docker-compose logs"
    exit 1
fi
