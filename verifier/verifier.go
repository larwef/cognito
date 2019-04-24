package verifier

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrIssuerDoesntMatch is returned when the issuer of the token doesn't match the issuer configured on the JWTVerifier.
	ErrIssuerDoesntMatch = errors.New("token issuer does not match verifier issuer")

	// ErrMissingPublicKey is returned when the JWTVerifyer doesn't contain a public key with the right kid.
	ErrMissingPublicKey = errors.New("verifier does not contain the right public key")

	// ErrInvalidSignature is returned when the signature doesnt match.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrTokenExpired is returned when the token has expired.
	ErrTokenExpired = errors.New("token has expired")

	// ErrUnexpectedAlg is returned when a token with unsupported signing method is received.
	ErrUnexpectedAlg = errors.New("unexpected signing algorithm. Currently only RS256 is supported")

	// ErrNoPublicKeysFound is returned if the response from the keys endpoint is empty for any reason.
	ErrNoPublicKeysFound = errors.New("found no public keys")
)

type key struct {
	Alg    string `json:"alg"`
	E      string `json:"e"`
	Kid    string `json:"kid"`
	Kty    string `json:"kty"`
	N      string `json:"n"`
	Use    string `json:"use"`
	pubKey *rsa.PublicKey
}

type keyResp struct {
	Keys []key `json:"keys"`
}

// JWTVerifier is used to parse and verify JWT tokens from a specific Issuer.
type JWTVerifier struct {
	Client *http.Client
	Issuer string
	keys   map[string]key
}

// Parse parses a token string and returns the parsed token if valid.
func (jv *JWTVerifier) Parse(token string) (*JWTToken, error) {
	return jv.parse(token, time.Now())
}

func (jv *JWTVerifier) parse(token string, timeStamp time.Time) (*JWTToken, error) {
	if len(jv.keys) <= 0 {
		if err := jv.getPublicKeys(); err != nil {
			return nil, err
		}
	}

	jwtToken, err := ParseJWT(token)
	if err != nil {
		return nil, fmt.Errorf("error parsing jwt token: %v", err)
	}

	if jwtToken.GetIssuer() != jv.Issuer {
		return nil, ErrIssuerDoesntMatch
	}

	if timeStamp.After(jwtToken.GetExpiration()) {
		return nil, ErrTokenExpired
	}

	if err := jv.verifySignature(jwtToken); err != nil {
		return nil, err
	}

	return jwtToken, nil
}

func (jv *JWTVerifier) verifySignature(token *JWTToken) error {
	if token.Header.Alg != "RS256" {
		return ErrUnexpectedAlg
	}

	key, exists := jv.keys[token.Header.Kid]
	if !exists {
		return ErrMissingPublicKey
	}

	h := sha256.New()
	h.Write([]byte(token.RawHeader))
	h.Write([]byte("."))
	h.Write([]byte(token.RawPayload))

	err := rsa.VerifyPKCS1v15(key.pubKey, crypto.SHA256, h.Sum(nil), token.Signature)
	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}

func (jv *JWTVerifier) getPublicKeys() error {
	if jv.Client == nil {
		jv.Client = http.DefaultClient
	}

	if jv.keys == nil {
		jv.keys = make(map[string]key)
	}

	keysURL := jv.Issuer + "/.well-known/jwks.json"
	res, err := jv.Client.Get(keysURL)
	if err != nil {
		return fmt.Errorf("unable to get keysRes from %s. Error: %v", keysURL, err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("unable to get keysRes from %s. Http statuscode: %d", keysURL, res.StatusCode)
	}

	var keysRes keyResp
	if err := json.NewDecoder(res.Body).Decode(&keysRes); err != nil {
		return fmt.Errorf("unable to unmarshal JWKS response from issuer: %v", err)
	}

	if len(keysRes.Keys) < 1 {
		return ErrNoPublicKeysFound
	}

	for _, key := range keysRes.Keys {
		if key.Use == "sig" {
			nBytes, err := decodeWithPadding(key.N)
			if err != nil {
				return fmt.Errorf("error parsing public key modulo(n): %v", err)
			}

			eBytes, err := decodeWithPadding(key.E)
			if err != nil {
				return fmt.Errorf("error parsing public key exponential(e): %v", err)
			}

			key.pubKey = &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(nBytes),
				E: int(big.NewInt(0).SetBytes(eBytes).Int64()),
			}
			jv.keys[key.Kid] = key
		}
	}

	return nil
}

// Pads before decoding if necessary
func decodeWithPadding(encoded string) ([]byte, error) {
	if l := len(encoded) % 4; l > 0 {
		encoded += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(encoded)
}
