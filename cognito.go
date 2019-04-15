package cognito

import (
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
)

// Config holds configuration info for the cognito http client
type Config struct {
	UserpoolID string
	ClientID   string
	Username   string
	Password   string
	AWSConfig  *aws.Config
}

// Client returns a new http.Client which will handle authentication with Cognito
func (c *Config) Client() (*http.Client, error) {
	ts, err := NewTokenSource(c)
	if err != nil {
		return nil, fmt.Errorf("error getting Token source: %v", err)
	}
	return &http.Client{
		Transport: &transport{
			tknSrc: ts,
		},
	}, nil
}
