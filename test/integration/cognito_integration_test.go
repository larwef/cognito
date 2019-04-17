package integration

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/larwef/cognito"
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
	var region = ""
	var testURL = "eu-west-1"

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

	payloadBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("error getting payload: %v", err)
	}

	fmt.Println(string(payloadBytes))
}
