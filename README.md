[![Go Report Card](https://goreportcard.com/badge/github.com/larwef/cognito)](https://goreportcard.com/report/github.com/larwef/cognito)

# Cognito
Library to obtain and verify JWT tokens from AWS Cognito.

## Client
Use the Config object to configure and obtain a http.Client which will handle authentication with Cognito and
add the Authentication header to all requests. Eg:

```
awsConf := &aws.Config{
    Region: aws.String("eu-west-1"),
}

conf := &client.Config{
    UserpoolID: "yourUserpoolId",   // "Pool Id" property in Cognito AWS Console.
    ClientID:   clientID,           // Found under "App Clients" in console.
    Username:   username,           // Username of the user to authenticate with.
    Password:   password,           // Password of the user to authenticate with.
    AWSConfig:  awsConf,            // AWS Config to use. Can be anonymous.
}

client, err := conf.Client()
if err != nil {
    t.Errorf("error getting client: %v", err)
}

response, err := client.Get("https://someUrl.com")
	
```

## Verifier
Configure a verifier with the location of the JSON Web Key Set(JWKS) and use the Parse function to verify the
token. The parse function will return a JWTToken object and nil error if successful.

```
jwtVerifier := verifier.JWTVerifier{
    Issuer: "https://cognito-idp.<your region>.amazonaws.com/<your pool id>",
}

_, err := jwtVerifier.Parse(tokenString)
if err != nil {
    t.Errorf("Parse returned an error: %v", err)
}
```
