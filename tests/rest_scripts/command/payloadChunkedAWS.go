package command

import (
	"encoding/hex"
	"strings"

	"github.com/versity/versitygw/tests/rest_scripts/logger"
)

type PayloadChunkedAWS struct {
	*PayloadChunked
	serviceString      string
	currentDateTime    string
	yyyymmdd           string
	lastSignature      string
	emptyByteSignature string
	signingKey         []byte
}

func (c *PayloadChunkedAWS) getChunkedSTSSignature(chunkSignature string) string {
	request := strings.Join([]string{"AWS4-HMAC-SHA256-PAYLOAD",
		c.currentDateTime,
		c.serviceString,
		c.lastSignature,
		c.emptyByteSignature,
		chunkSignature}, "\n")
	logger.PrintDebug("request: %s", request)
	canonicalRequestHashBytes := hmacSHA256(c.signingKey, request)
	return hex.EncodeToString(canonicalRequestHashBytes[:])
}
