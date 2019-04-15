package cognito

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	cip "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
)

func TestTokenSource_getToken(t *testing.T) {
	cognitoMock := &mockCognito{}
	ts := getTokenSource(cognitoMock)

	cognitoMock.respondToAuthChallengeHandler = func(*cip.RespondToAuthChallengeInput) (*cip.RespondToAuthChallengeOutput, error) {
		return &cip.RespondToAuthChallengeOutput{
			AuthenticationResult: &cip.AuthenticationResultType{
				AccessToken:  aws.String("AccessToken"),
				IdToken:      aws.String("IDToken"),
				RefreshToken: aws.String("RefreshToken"),
				ExpiresIn:    aws.Int64(3600),
				TokenType:    aws.String("Bearer"),
			},
		}, nil
	}

	tkn, err := ts.GetToken()
	if err != nil {
		t.Errorf("GetToken returned an error: %v", err)
	}

	if tkn.AccessToken != "AccessToken" {
		t.Error("AccessToken has unecpected value")
	}

	if tkn.IDToken != "IDToken" {
		t.Error("IDToken has unecpected value")
	}

	if tkn.RefreshToken != "RefreshToken" {
		t.Error("RefreshToken has unecpected value")
	}
}

func TestTokenSource_getToken_NewPasswordRequired(t *testing.T) {
	cognitoMock := &mockCognito{}
	ts := getTokenSource(cognitoMock)

	cognitoMock.respondToAuthChallengeHandler = func(rac *cip.RespondToAuthChallengeInput) (*cip.RespondToAuthChallengeOutput, error) {
		// Will only return the Token if called with NEW_PASSWORD_REQUIRED which means the program will have had to go through the
		// change password flow to pass the assertions at the bottom of the test.
		if *rac.ChallengeName == "NEW_PASSWORD_REQUIRED" {
			return &cip.RespondToAuthChallengeOutput{
				AuthenticationResult: &cip.AuthenticationResultType{
					AccessToken:  aws.String("AccessToken"),
					IdToken:      aws.String("IDToken"),
					RefreshToken: aws.String("RefreshToken"),
					ExpiresIn:    aws.Int64(3600),
					TokenType:    aws.String("Bearer"),
				},
			}, nil
		}

		return &cip.RespondToAuthChallengeOutput{
			ChallengeName:       aws.String("NEW_PASSWORD_REQUIRED"),
			ChallengeParameters: map[string]*string{},
			Session:             aws.String("session"),
		}, nil

	}

	cognitoMock.changePasswordHandler = func(cpi *cip.ChangePasswordInput) (*cip.ChangePasswordOutput, error) {
		if *cpi.AccessToken != "AccessToken" {
			t.Error("Unexpected value for AccessToken")
		}
		if !strings.Contains(*cpi.PreviousPassword, "password") {
			t.Error("Unexpected value for PreviousPassword")
		}
		if *cpi.ProposedPassword != ts.config.Password {
			t.Errorf("Unexpected value: %v for ProposedPassword. Expected: %v", *cpi.ProposedPassword, ts.config.Password)
		}
		return &cip.ChangePasswordOutput{}, nil
	}

	tkn, err := ts.GetToken()
	if err != nil {
		t.Errorf("GetToken returned an error: %v", err)
	}

	if tkn.AccessToken != "AccessToken" {
		t.Error("AccessToken has unecpected value")
	}

	if tkn.IDToken != "IDToken" {
		t.Error("IDToken has unecpected value")
	}

	if tkn.RefreshToken != "RefreshToken" {
		t.Error("RefreshToken has unecpected value")
	}
}

func TestTokenSource_getToken_ExistingToken(t *testing.T) {
	ts := getTokenSource(nil)
	ts.tkn.AccessToken = "AccessToken"
	ts.tkn.Expiration = time.Now().Add(1 * time.Hour)

	tkn, err := ts.GetToken()
	if err != nil {
		t.Errorf("GetToken returned an error: %v", err)
	}

	if tkn.AccessToken != "AccessToken" {
		t.Errorf("Unexpected value: %v for AccessToken. Expected: %v", tkn.AccessToken, "AccessToken")
	}
}

func TestTokenSource_getToken_ExpiredToken_WithRefreshToken(t *testing.T) {
	cognitoMock := &mockCognito{}
	ts := getTokenSource(cognitoMock)
	ts.tkn.AccessToken = "oldAccessToken"
	ts.tkn.RefreshToken = "oldRefreshToken"
	ts.tkn.Expiration = time.Now().Add(-1 * time.Minute)

	tkn, err := ts.GetToken()
	if err != nil {
		t.Errorf("GetToken returned an error: %v", err)
	}

	if tkn.AccessToken != "refreshedAccessToken" {
		t.Error("AccessToken has unecpected value")
	}

	if tkn.IDToken != "refreshedIdToken" {
		t.Error("IDToken has unecpected value")
	}
}

func TestTokenSource_getToken_ExpiredToken_WithoutRefreshToken(t *testing.T) {
	cognitoMock := &mockCognito{}
	ts := getTokenSource(cognitoMock)
	ts.tkn.AccessToken = "oldAccessToken"
	ts.tkn.RefreshToken = ""
	ts.tkn.Expiration = time.Now().Add(-1 * time.Minute)

	cognitoMock.respondToAuthChallengeHandler = func(*cip.RespondToAuthChallengeInput) (*cip.RespondToAuthChallengeOutput, error) {
		return &cip.RespondToAuthChallengeOutput{
			AuthenticationResult: &cip.AuthenticationResultType{
				AccessToken:  aws.String("AccessToken"),
				IdToken:      aws.String("IDToken"),
				RefreshToken: aws.String("RefreshToken"),
				ExpiresIn:    aws.Int64(3600),
				TokenType:    aws.String("Bearer"),
			},
		}, nil
	}

	tkn, err := ts.GetToken()
	if err != nil {
		t.Errorf("GetToken returned an error: %v", err)
	}

	if tkn.AccessToken != "AccessToken" {
		t.Error("AccessToken has unecpected value")
	}

	if tkn.IDToken != "IDToken" {
		t.Error("IDToken has unecpected value")
	}
}

// Mock and helper functions
type mockCognito struct {
	cognitoidentityprovideriface.CognitoIdentityProviderAPI
	initiateAuthhandler           func(*cip.InitiateAuthInput) (*cip.InitiateAuthOutput, error)
	respondToAuthChallengeHandler func(*cip.RespondToAuthChallengeInput) (*cip.RespondToAuthChallengeOutput, error)
	changePasswordHandler         func(*cip.ChangePasswordInput) (*cip.ChangePasswordOutput, error)
}

func (mc *mockCognito) InitiateAuth(iau *cip.InitiateAuthInput) (*cip.InitiateAuthOutput, error) {
	if *iau.AuthFlow == cip.AuthFlowTypeRefreshTokenAuth {
		return &cip.InitiateAuthOutput{
			AuthenticationResult: &cip.AuthenticationResultType{
				AccessToken: aws.String("refreshedAccessToken"),
				IdToken:     aws.String("refreshedIdToken"),
				ExpiresIn:   aws.Int64(3600),
				TokenType:   aws.String("Bearer"),
			},
		}, nil
	}
	// The result here doesnt really matter. Just has to go through the computations ok.
	return &cip.InitiateAuthOutput{
		ChallengeName: aws.String("PASSWORD_VERIFIER"),
		ChallengeParameters: map[string]*string{
			"USER_ID_FOR_SRP:": aws.String("testUser"),
			"SALT":             aws.String("3ca406766400a19acc45ee6bce26d7e2"),
			"SECRET_BLOCK":     aws.String("4zH+DcCEFqb+3MTPaKCq6RkkoO7gyAWh9PyL0uxno4gjL3sVS4j/CAhckXVxF06IwaggYmBev6Sd+sBhGRabc2I+dkfvdWZDlpL9qgPtg26NN0Dn/9l6xuTv+w8WjGx3O8R1fHgpBQwvROebL7cwmVn+XsF6Inb1Hfx6W+h+afqEPC6FiNGKgqVfXUNHGQBcqGO9cfD28/rGpIY9BDlDe6+qKJ1YeVYhAXbQdEW2C16zmMjSVM9npaeM7xyn/DDiQMa6eumBv04edL2L0DUL9/rGd1LoYgMWMoQDsiInRzjCu85ffFUunpPGirPyQppdVP5y45fVhqhaSAqH62wgu6XTsaufXt1imAThnXIvgBCvWe9ju39VSHYqkonNO2XMDdM4oEmCHL39Zp/As4pw+QGuz3zJmvUOjF5eUC4nFgbsobgUTkDj9+Q/KMfRoM5NeucwLrGeaS4NPgYWbnWIFE1X669MDO2VtOa2BSEUVu6Ic5dgYY0RTS6s2gfegC6slouxiAU7m+6IyavqknIPh7SXT8xd5awM3WXqzcTDiX0vIZn5arvoPnp0t+vdONq6omX0TX/4uqs71aPD4xoDK4UPmY5IXzRwiznIC9E8KTjvoH8aw+ZXFuCu5xdGwohJjLSRN/addJZCzrlBMQeEJI4VsQIpPo59LFjFmw4ySMJLy/4YcBypihX02KHzxkcnfN/u7mVGqWi5KLAiDCVdK38BJlNL/JtqavSaaVAtdeZGB2rgLIpxls+UpNI5qgF42UODey0C6HXTAvsRcxmC+Rk3ZR3PPu66KkkP6++m90s3ijsUhqad3RCK8wKq5xC8wI746ag7/VVEfwX+DVSoJh8ciReNT3EjwNHLT1VsA5an+yQcE2KtlG2l+4B5B0QWCfr/J7k2LJKu4Ri8wIChegfJr0Ju/OQC0IjLJzDdcefJsHTF1yoQW7jrJTce+Y/UF//KY4k1YNTdWiE/X9xZMoqbTLRYb7Q9YfcjSS/HpOnrHt4i4Wx31EWXpw8CweB4xwPCiGmRC07ZvSkNxkUOskbaX+zSPB6phnUw2JPY0iBv+JBEGI+e67dkSYWRi+cYiGHP7l6I2zegtl1ez8T6NsE/jfkXxD633xQDcmg+RAtR07vzvSOTYfPbBZpj8GWe9V9YouP30xRTBMe8bYjWSijI/HfQpGSYjorHSUgUb+oefOj2R/3Scrr2OA4yfjh8OQ3uZReqlA3VCeVxRI90sHDRjU0PV0kKX5PrO9Z4RuoKDSbQvNI4yzOxlWEo0KQJLbwNn+0Lp/a5RAk4hbj578LesKYQUE2GCFzj91NL9zB9JUHd4MfF3Gl9gzDqF2K5gJSPfNg6OfJ5VODVrNWATgzEDj+LmL120Zyfo1P3B6ZluQhl2tYN8Ht+SVSUEDmXHyJ7SNiYOUieRNLfpACe5McrSLWz5wBjXxj/XnfzKLzu/89KvtbbPd5J9lrflYJwsOHuvJuY4Ws+O0J7hO2gqPvQH0dhbxoJHT2qFodF5a0+AhHQ5m+i0krAfpHCzV6GBeFAMLyWtYtjwmePSfHDYQcznj5H8Qc7Dyd5u95k0yGvOH26Uj0xbKfoX5mO5H395FXiQPhKimtqR4LcmLtlTEkC06lfwbMUPMwogq2QHpwgoagxqutkI1z4hYo/94JyAEtgtb68TUeIqY2tQAkvQ9IwrtXqSwe58O8Q0JQbq6xQId3Ll6UyDVoOnVY="),
			"SRP_B":            aws.String("36691328af94a9a0eaf96f10c1d884df83cf40cc440b7a63f48aede0e741d8d22e0dc7765f9fb51ee99919d1072e75b1671bc513e46a5c82cd1b7bb27937ee55a2d3dba38079f72fa130db6a2e9b8ce052020126c8376cd95e54700c655a011b9b90f4bb315acb5006151d00a5e83af54eca9e3ce446d266f4ccef0f6bca0534b0251e5e6f15eb20308948cac77b0aab4b18a4e2369de783e5eae5f38d3f57a5bf4f8be485c75d78695d18843db3579cd301b6800a206d2b438b6fe11037b3fb39b26f40d4ce15d824e80198cc2736bb8aea6cc2a6241aebf58ca1de84391b2246c0eb2217b89795098d4821d1922f7889fb86314483947585201196d4c635b6d9559c2c920283c638fa2d60a9d933dc2a3b2622318dc67b4c75174296218ca1a4c372f90195d61342f7374a950dd48728e0a2d5f1f2caf1839ae7d45c5f915726097726dd7819283c86f7656f94e7034df892d0e490ba0d9a1f6fba4a59e55630f054daf48ed07a49b47499a1cb87cf5291abd9f3ceec6933016b42f0a704d3"),
			"USERNAME":         aws.String("testUser"),
		},
	}, nil
}

func (mc *mockCognito) RespondToAuthChallenge(rac *cip.RespondToAuthChallengeInput) (*cip.RespondToAuthChallengeOutput, error) {
	return mc.respondToAuthChallengeHandler(rac)
}

func (mc *mockCognito) ChangePassword(cpi *cip.ChangePasswordInput) (*cip.ChangePasswordOutput, error) {
	return mc.changePasswordHandler(cpi)
}

func getTokenSource(mock cognitoidentityprovideriface.CognitoIdentityProviderAPI) *TokenSource {
	conf := &Config{
		UserpoolID: "eu-west-1_userpoolId",
		ClientID:   "clientId",
		Username:   "user",
		Password:   "password",
	}

	return &TokenSource{
		config:           conf,
		userpoolName:     "userpoolId",
		identityProvider: mock,
	}
}
