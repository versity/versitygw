// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/s3proxy"
)

var (
	s3multiConfigFile string
	s3multiDebug      bool
)

// S3BackendConfig represents configuration for a single S3 backend
type S3BackendConfig struct {
	Name            string `json:"name"`            // Human-readable name for this backend
	Access          string `json:"access"`          // Access key
	Secret          string `json:"secret"`          // Secret key
	Endpoint        string `json:"endpoint"`        // S3 endpoint URL
	Region          string `json:"region"`          // AWS region
	MetaBucket      string `json:"metaBucket"`      // Meta bucket for ACLs/policies
	DisableChecksum bool   `json:"disableChecksum"` // Disable checksums
	SslSkipVerify   bool   `json:"sslSkipVerify"`   // Skip SSL verification
	UsePathStyle    bool   `json:"usePathStyle"`    // Use path-style addressing
}

// S3MultiConfig represents configuration for multiple S3 backends
type S3MultiConfig struct {
	Backends []S3BackendConfig `json:"backends"`
}

func s3MultiCommand() *cli.Command {
	return &cli.Command{
		Name:  "s3-multi",
		Usage: "multiple s3 storage backends with fallback",
		Description: `This runs the gateway with multiple S3 backends for fallback support.
When an object is not found in the first backend, it automatically tries the next backend.

Read operations (GET, HEAD, LIST) will try all backends in order until the object is found.
Write operations (PUT, DELETE) always go to the first (primary) backend.

Configuration is provided via a JSON file with the following structure:
{
  "backends": [
    {
      "name": "primary-s3",
      "access": "ACCESS_KEY_1",
      "secret": "SECRET_KEY_1",
      "endpoint": "https://s3-primary.example.com",
      "region": "us-east-1",
      "metaBucket": "meta-bucket-1",
      "disableChecksum": false,
      "sslSkipVerify": false,
      "usePathStyle": false
    },
    {
      "name": "fallback-s3",
      "access": "ACCESS_KEY_2",
      "secret": "SECRET_KEY_2",
      "endpoint": "https://s3-fallback.example.com",
      "region": "us-west-2",
      "metaBucket": "",
      "disableChecksum": false,
      "sslSkipVerify": false,
      "usePathStyle": true
    }
  ]
}

Environment variables can also be used with the format VGW_S3_MULTI_BACKEND_N_FIELD,
where N is the backend index (0, 1, 2, etc.) and FIELD is the configuration field name in uppercase.

Example:
  VGW_S3_MULTI_BACKEND_0_ACCESS=key1
  VGW_S3_MULTI_BACKEND_0_SECRET=secret1
  VGW_S3_MULTI_BACKEND_0_ENDPOINT=https://s3-1.example.com
  VGW_S3_MULTI_BACKEND_1_ACCESS=key2
  VGW_S3_MULTI_BACKEND_1_SECRET=secret2
  VGW_S3_MULTI_BACKEND_1_ENDPOINT=https://s3-2.example.com
`,
		Action: runS3Multi,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Usage:       "path to JSON configuration file with S3 backend definitions",
				Required:    true,
				EnvVars:     []string{"VGW_S3_MULTI_CONFIG"},
				Destination: &s3multiConfigFile,
				Aliases:     []string{"c"},
			},
			&cli.BoolFlag{
				Name:        "debug",
				Usage:       "output extra debug tracing for multi-backend operations",
				Value:       false,
				EnvVars:     []string{"VGW_S3_MULTI_DEBUG"},
				Destination: &s3multiDebug,
			},
		},
	}
}

func runS3Multi(ctx *cli.Context) error {
	// Generate random credentials if not provided
	if rootUserAccess == "" {
		rootUserAccess = generateRandomCredential(20)
		if rootUserAccess == "" {
			return fmt.Errorf("failed to generate access key and none provided via --access flag")
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "⚠️  Generated random ACCESS KEY: %s\n", rootUserAccess)
		}
	}
	if rootUserSecret == "" {
		rootUserSecret = generateRandomCredential(40)
		if rootUserSecret == "" {
			return fmt.Errorf("failed to generate secret key and none provided via --secret flag")
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "⚠️  Generated random SECRET KEY: %s\n", rootUserSecret)
		}
	}

	// Load configuration from file
	config, err := loadS3MultiConfig(s3multiConfigFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if len(config.Backends) == 0 {
		return fmt.Errorf("at least one backend must be configured")
	}

	if s3multiDebug {
		fmt.Fprintf(os.Stderr, "Initializing multi-backend with %d backends:\n", len(config.Backends))
	}

	// Create all backend instances
	backends := make([]backend.Backend, 0, len(config.Backends))
	for i, backendCfg := range config.Backends {
		if s3multiDebug {
			fmt.Fprintf(os.Stderr, "  [%d] %s - endpoint: %s, region: %s\n",
				i, backendCfg.Name, backendCfg.Endpoint, backendCfg.Region)
		}

		// Validate required fields
		if backendCfg.Access == "" {
			return fmt.Errorf("backend %d (%s): access key is required", i, backendCfg.Name)
		}
		if backendCfg.Secret == "" {
			return fmt.Errorf("backend %d (%s): secret key is required", i, backendCfg.Name)
		}

		// Set defaults
		if backendCfg.Region == "" {
			backendCfg.Region = "us-east-1"
		}

		// Create S3 proxy backend
		be, err := s3proxy.New(
			ctx.Context,
			backendCfg.Access,
			backendCfg.Secret,
			backendCfg.Endpoint,
			backendCfg.Region,
			backendCfg.MetaBucket,
			backendCfg.DisableChecksum,
			backendCfg.SslSkipVerify,
			backendCfg.UsePathStyle,
			s3multiDebug || s3proxyDebug, // Enable debug if either flag is set
		)
		if err != nil {
			return fmt.Errorf("init s3 backend %d (%s): %w", i, backendCfg.Name, err)
		}

		backends = append(backends, be)
	}

	// Wrap backends in multi-backend
	multiBackend, err := backend.NewMultiBackend(backends...)
	if err != nil {
		return fmt.Errorf("create multi-backend: %w", err)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Multi-backend initialized with %d S3 backends\n", len(config.Backends))
		fmt.Fprintf(os.Stderr, "Primary backend: %s\n", config.Backends[0].Name)
		if len(config.Backends) > 1 {
			fmt.Fprintf(os.Stderr, "Fallback backends: ")
			for i := 1; i < len(config.Backends); i++ {
				if i > 1 {
					fmt.Fprintf(os.Stderr, ", ")
				}
				fmt.Fprintf(os.Stderr, "%s", config.Backends[i].Name)
			}
			fmt.Fprintf(os.Stderr, "\n")
		}
	}

	return runGateway(ctx.Context, multiBackend)
}

func loadS3MultiConfig(configPath string) (*S3MultiConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config S3MultiConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config JSON: %w", err)
	}

	// Validate configuration
	if len(config.Backends) == 0 {
		return nil, fmt.Errorf("no backends defined in configuration")
	}

	// Apply environment variable overrides
	config, err = applyEnvOverrides(config)
	if err != nil {
		return nil, fmt.Errorf("apply environment overrides: %w", err)
	}

	return &config, nil
}

func applyEnvOverrides(config S3MultiConfig) (S3MultiConfig, error) {
	// Check for environment variable overrides
	// Format: VGW_S3_MULTI_BACKEND_N_FIELD where N is index
	for i := range config.Backends {
		prefix := fmt.Sprintf("VGW_S3_MULTI_BACKEND_%d_", i)

		if val := os.Getenv(prefix + "NAME"); val != "" {
			config.Backends[i].Name = val
		}
		if val := os.Getenv(prefix + "ACCESS"); val != "" {
			config.Backends[i].Access = val
		}
		if val := os.Getenv(prefix + "SECRET"); val != "" {
			config.Backends[i].Secret = val
		}
		if val := os.Getenv(prefix + "ENDPOINT"); val != "" {
			config.Backends[i].Endpoint = val
		}
		if val := os.Getenv(prefix + "REGION"); val != "" {
			config.Backends[i].Region = val
		}
		if val := os.Getenv(prefix + "META_BUCKET"); val != "" {
			config.Backends[i].MetaBucket = val
		}
		if val := os.Getenv(prefix + "DISABLE_CHECKSUM"); val != "" {
			if boolVal, err := strconv.ParseBool(val); err == nil {
				config.Backends[i].DisableChecksum = boolVal
			} else {
				fmt.Fprintf(os.Stderr, "WARNING: failed to parse boolean for %sDISABLE_CHECKSUM: '%s' (%v)\n", prefix, val, err)
			}
		}
		if val := os.Getenv(prefix + "SSL_SKIP_VERIFY"); val != "" {
			if boolVal, err := strconv.ParseBool(val); err == nil {
				config.Backends[i].SslSkipVerify = boolVal
			} else {
				fmt.Fprintf(os.Stderr, "WARNING: failed to parse boolean for %sSSL_SKIP_VERIFY: '%s' (%v)\n", prefix, val, err)
			}
		}
		if val := os.Getenv(prefix + "USE_PATH_STYLE"); val != "" {
			if boolVal, err := strconv.ParseBool(val); err == nil {
				config.Backends[i].UsePathStyle = boolVal
			} else {
				fmt.Fprintf(os.Stderr, "WARNING: failed to parse boolean for %sUSE_PATH_STYLE: '%s' (%v)\n", prefix, val, err)
			}
		}
	}

	return config, nil
}

// generateRandomCredential generates a cryptographically secure random credential
// Returns empty string on error to allow graceful handling
func generateRandomCredential(length int) string {
	// Calculate bytes needed: base64 encoding expands data by 4/3
	// To get 'length' characters of base64, we need length * 3/4 bytes (rounded up)
	bytesNeeded := (length*3 + 3) / 4 // Round up to handle base64 padding
	bytes := make([]byte, bytesNeeded)
	if _, err := rand.Read(bytes); err != nil {
		// Return empty string on error - caller should check and handle appropriately
		fmt.Fprintf(os.Stderr, "ERROR: Failed to generate random credential: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please provide credentials manually using --access and --secret flags\n")
		return ""
	}

	// Encode to base64 and trim to exact desired length
	encoded := base64.URLEncoding.EncodeToString(bytes)
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded
}
