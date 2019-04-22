package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// JWTToken represents a token sent by a client.
type JWTToken struct {
	Raw       string
	Header    JWTHeader
	Claims    map[string]interface{}
	Signature []byte
}

// JWTHeader holds the header information of the jwt token.
type JWTHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// ParseJWT parses a token string to a JWTToken object. Returns a JWTToken object and nil if successful. Otherwise a nil and an error.
func ParseJWT(token string) (*JWTToken, error) {
	split := strings.Split(token, ".")
	if len(split) < 3 {
		return nil, errors.New("uanble to parse token. Not enough elements after split")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(split[0])
	if err != nil {
		return nil, fmt.Errorf("unable to decode header: %v", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(split[1])
	if err != nil {
		return nil, fmt.Errorf("unable to decode payload: %v", err)
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(split[2])
	if err != nil {
		return nil, fmt.Errorf("unable to decode signature: %v", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unable to unmarshal header: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("unable to unmarshal payload: %v", err)
	}

	return &JWTToken{
		Raw:       token,
		Header:    header,
		Claims:    payload,
		Signature: signatureBytes,
	}, nil
}

// GetIssuer returns the issuer(iss) attribute from the jwt token.
func (jt *JWTToken) GetIssuer() string {
	return jt.Claims["iss"].(string)
}

// GetExpiration returns the expiration(exp) attribute from the jwt token.
func (jt *JWTToken) GetExpiration() time.Time {
	return time.Unix(int64(jt.Claims["exp"].(float64)), 0)
}
