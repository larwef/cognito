// +build integration

package integration

import (
	"github.com/rejlersembriq/cognito/verifier"
	"testing"
)

func TestJWTVerifier(t *testing.T) {
	var issuer = ""
	var testToken = ""

	jwtVerifier := verifier.JWTVerifier{
		Issuer: issuer,
	}

	_, err := jwtVerifier.Parse(testToken)
	if err != nil {
		t.Errorf("Parse returned an error: %v", err)
	}
}
