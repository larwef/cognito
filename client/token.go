package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	cip "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/google/uuid"
)

const metadataAuthorizationFieldName string = "authorization"

const timestampFormat string = "Mon Jan 2 15:04:05 MST 2006"

// Token holds the credentials received from Cognito
type Token struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	TokenType    string
	Expiration   time.Time
}

func (t *Token) updateToken(authenticationResult *cip.AuthenticationResultType) *Token {
	t.AccessToken = aws.StringValue(authenticationResult.AccessToken)
	t.IDToken = aws.StringValue(authenticationResult.IdToken)
	t.RefreshToken = aws.StringValue(authenticationResult.RefreshToken)
	t.TokenType = aws.StringValue(authenticationResult.TokenType)
	t.Expiration = time.Now().Add(time.Duration(*authenticationResult.ExpiresIn) * time.Second)

	return t
}

func (t *Token) setAuthHeader(r *http.Request) {
	//r.Header.Set("Authorization", t.TokenType+" "+t.IDToken)
	r.Header.Set("Authorization", t.IDToken)
}

func (t *Token) getRequestMetadata() map[string]string {
	metadata := make(map[string]string)
	metadata[metadataAuthorizationFieldName] = t.TokenType + " " + t.IDToken
	return metadata
}

// TokenSource handles the retrieval and refreshing of tokens
type TokenSource struct {
	config           *Config
	userpoolName     string
	identityProvider cognitoidentityprovideriface.CognitoIdentityProviderAPI
	tkn              Token
}

// NewTokenSource returns a new TokenSource with the provided configuration
func NewTokenSource(conf *Config) (*TokenSource, error) {
	sess, err := session.NewSession(conf.AWSConfig)
	if err != nil {
		return nil, fmt.Errorf("error getting Cognito session: %v", err)
	}

	ts := &TokenSource{
		config:           conf,
		userpoolName:     strings.Split(conf.UserpoolID, "_")[1],
		identityProvider: cip.New(sess),
	}

	return ts, nil
}

// GetRequestMetadata is used to implement PerRPCCredentials interface.
func (ts *TokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token, err := ts.GetToken()
	if err != nil {
		return nil, err
	}

	return token.getRequestMetadata(), nil
}

// RequireTransportSecurity is used to implement PerRPCCredentials interface.
// TODO: Make this default to true.
func (ts *TokenSource) RequireTransportSecurity() bool {
	return ts.config.RequireTransportSecurity
}

// GetToken returns the existing Token if valid or refreshes and returns the new Token.
func (ts *TokenSource) GetToken() (*Token, error) {
	if ts.tkn.AccessToken != "" && time.Now().Before(ts.tkn.Expiration) {
		return &ts.tkn, nil
	}

	if ts.tkn.RefreshToken != "" {
		authResponse, err := ts.refreshAuthToken()
		if err != nil {
			return nil, fmt.Errorf("error refreshing Token: %v", err)
		}

		return ts.tkn.updateToken(authResponse), nil
	}

	authResponse, err := ts.authenticate()
	if err != nil {
		return nil, fmt.Errorf("error retrieving Token: %v", err)
	}

	return ts.tkn.updateToken(authResponse), nil
}

func (ts *TokenSource) authenticate() (*cip.AuthenticationResultType, error) {
	s, err := newSrp(generatePrivateKey())
	if err != nil {
		return nil, fmt.Errorf("error initiating srp: %v", err)
	}

	iar, err := ts.signIn(s)
	if err != nil {
		return nil, fmt.Errorf("error initiating auth: %v", err)
	}

	rtac, err := ts.respondPasswordVerifier(iar, s)
	if err != nil {
		return nil, fmt.Errorf("error responding to auth challenge: %v", err)
	}

	if rtac.ChallengeName != nil && *rtac.ChallengeName == "NEW_PASSWORD_REQUIRED" {
		tmpPassword := ts.config.Password + ":" + uuid.New().String()
		res, err := ts.respondNewPasswordRequired(rtac, tmpPassword)

		if err != nil {
			return nil, fmt.Errorf("error setting new password: %v", err)
		}

		ts.tkn.updateToken(res.AuthenticationResult)
		if err := ts.changePassword(tmpPassword, ts.config.Password); err != nil {
			return nil, fmt.Errorf("error changing password: %v", err)
		}

		return res.AuthenticationResult, nil
	}

	return rtac.AuthenticationResult, nil
}

func (ts *TokenSource) signIn(s *srp) (*cip.InitiateAuthOutput, error) {
	params := &cip.InitiateAuthInput{
		AuthFlow: aws.String(cip.AuthFlowTypeUserSrpAuth),
		AuthParameters: map[string]*string{
			"USERNAME": &ts.config.Username,
			"SRP_A":    aws.String(s.getA().Text(16)),
		},
		ClientId: &ts.config.ClientID,
	}

	return ts.identityProvider.InitiateAuth(params)
}

func (ts *TokenSource) respondPasswordVerifier(initAuthResponse *cip.InitiateAuthOutput, s *srp) (*cip.RespondToAuthChallengeOutput, error) {
	salt, ok := big.NewInt(0).SetString(*initAuthResponse.ChallengeParameters["SALT"], 16)
	if !ok {
		return nil, fmt.Errorf("error parsing salt value: %s", *initAuthResponse.ChallengeParameters["SALT"])
	}

	xB, ok := big.NewInt(0).SetString(*initAuthResponse.ChallengeParameters["SRP_B"], 16)
	if !ok {
		return nil, fmt.Errorf("error parsing B value: %s", *initAuthResponse.ChallengeParameters["SALT"])
	}

	secretBlock, err := base64.StdEncoding.DecodeString(*initAuthResponse.ChallengeParameters["SECRET_BLOCK"])
	if err != nil {
		return nil, fmt.Errorf("error parsing secret block: %s", *initAuthResponse.ChallengeParameters["SECRET_BLOCK"])
	}

	dateStr := time.Now().UTC().Format(timestampFormat)

	signature, err := s.getSignature(ts.userpoolName, ts.config.Username, ts.config.Password, dateStr, salt, xB, secretBlock)
	if err != nil {
		return nil, fmt.Errorf("error getting signature value: %v", err)
	}

	params := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: initAuthResponse.ChallengeName,
		ChallengeResponses: map[string]*string{
			"PASSWORD_CLAIM_SECRET_BLOCK": initAuthResponse.ChallengeParameters["SECRET_BLOCK"],
			"PASSWORD_CLAIM_SIGNATURE":    &signature,
			"TIMESTAMP":                   &dateStr,
			"USERNAME":                    &ts.config.Username,
		},
		ClientId: &ts.config.ClientID,
	}

	return ts.identityProvider.RespondToAuthChallenge(params)
}

func (ts *TokenSource) respondNewPasswordRequired(challengeOutput *cip.RespondToAuthChallengeOutput, newPassword string) (*cip.RespondToAuthChallengeOutput, error) {
	params := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: challengeOutput.ChallengeName,
		ChallengeResponses: map[string]*string{
			"USERNAME":     &ts.config.Username,
			"NEW_PASSWORD": &newPassword,
		},
		ClientId: &ts.config.ClientID,
		Session:  challengeOutput.Session,
	}

	return ts.identityProvider.RespondToAuthChallenge(params)
}

func (ts *TokenSource) changePassword(oldPassword, newPassword string) error {
	params := &cip.ChangePasswordInput{
		AccessToken:      &ts.tkn.AccessToken,
		PreviousPassword: &oldPassword,
		ProposedPassword: &newPassword,
	}

	_, err := ts.identityProvider.ChangePassword(params)
	return err
}

func (ts *TokenSource) refreshAuthToken() (*cip.AuthenticationResultType, error) {
	params := &cip.InitiateAuthInput{
		AuthFlow: aws.String(cip.AuthFlowTypeRefreshTokenAuth),
		AuthParameters: map[string]*string{
			"REFRESH_TOKEN": &ts.tkn.RefreshToken,
		},
		ClientId: &ts.config.ClientID,
	}

	res, err := ts.identityProvider.InitiateAuth(params)
	return res.AuthenticationResult, err
}
