// +build integration

package integration

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/larwef/cognito"
	"testing"
	"time"
)

// Run integrationtest with a fresh Cognito user which needs FORCE_CHANGE_PASSWORD.

var userpoolID = ""
var clientID = ""
var username = ""
var password = ""
var region = "eu-west-1"

func TestTokenSource(t *testing.T) {
	// Setup
	awsConf := &aws.Config{
		Region: aws.String(region),
	}

	conf := &cognito.Config{
		UserpoolID: userpoolID,
		ClientID:   clientID,
		Username:   username,
		Password:   password,
		AWSConfig:  awsConf,
	}

	tokenSource, err := cognito.NewTokenSource(conf)
	if err != nil {
		t.Errorf("Error getting TokenSource: %v", err)
	}

	// Run tests
	token := testForceChangePassword(t, tokenSource)
	token = testRefreshWithToken(t, token, tokenSource)
	token = testGetExistingToken(t, token, tokenSource)
	token = testRefreshWithoutToken(t, token, tokenSource)
}

func testForceChangePassword(t *testing.T, ts *cognito.TokenSource) *cognito.Token {
	token, err := ts.GetToken()
	if err != nil {
		t.Errorf("Error getting token: %v", err)
	}

	return token
}

func testGetExistingToken(t *testing.T, token *cognito.Token, ts *cognito.TokenSource) *cognito.Token {
	oldAccessToken := token.AccessToken

	token, err := ts.GetToken()
	if err != nil {
		t.Errorf("Error getting token: %v", err)
	}

	if token.AccessToken != oldAccessToken && token.AccessToken == "" {
		t.Error("AccessToken values before and after call are not equal or AccessToken is empty.")
	}

	return token
}

func testRefreshWithToken(t *testing.T, token *cognito.Token, ts *cognito.TokenSource) *cognito.Token {
	// Set expiration to trigger refresh.
	token.Expiration = time.Now().Add(-1 * time.Second)

	oldAccessToken := token.AccessToken

	token, err := ts.GetToken()
	if err != nil {
		t.Errorf("Error getting token: %v", err)
	}

	if token.AccessToken == oldAccessToken && token.AccessToken == "" {
		t.Error("New token is equal to the old token or empty.")
	}

	return token
}

func testRefreshWithoutToken(t *testing.T, token *cognito.Token, ts *cognito.TokenSource) *cognito.Token {
	// Set expiration to trigger refresh.
	token.Expiration = time.Now().Add(-1 * time.Second)
	// Make sure the RefreshToken is empty so a new authentication is performed.
	token.RefreshToken = ""

	oldAccessToken := token.AccessToken

	token, err := ts.GetToken()
	if err != nil {
		t.Errorf("Error getting token: %v", err)
	}

	if token.AccessToken == oldAccessToken && token.AccessToken == "" {
		t.Error("New token is equal to the old token or empty.")
	}

	return token
}
