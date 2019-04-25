// +build integration

package integration

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/rejlersembriq/cognito/client"
	"io/ioutil"
	"net/http"
	"testing"
)

// Test with a live endpoint that requires Cognito authentication

func TestCognito(t *testing.T) {
	var userpoolID = ""
	var clientID = ""
	var username = ""
	var password = ""
	var region = "eu-west-1"
	var testURL = ""

	// Setup
	awsConf := &aws.Config{
		Region: aws.String(region),
	}

	conf := &client.Config{
		UserpoolID: userpoolID,
		ClientID:   clientID,
		Username:   username,
		Password:   password,
		AWSConfig:  awsConf,
	}

	client, err := conf.Client()
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, testURL, nil)
	if err != nil {
		t.Errorf("error getting request: %v", err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Errorf("error from %s: %v", req.Method, err)
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		t.Errorf("response was outside http 200 range. Status code: %d received", res.StatusCode)
	}

	payloadBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("error getting payload: %v", err)
	}

	fmt.Println(string(payloadBytes))
}
