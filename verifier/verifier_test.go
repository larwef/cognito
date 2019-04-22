package verifier

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var validSignatureTestToken = "eyJraWQiOiJ5SmdkcHMzM3YxTmc5Tk1pWElDTXhGQU1DOTloMnA3VGxYWkFyMDlZaStvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0Zjc5ZTcyYi1jMjdlLTRiNzUtYjkzYy05MDk3YjZiNjhjZTkiLCJhdWQiOiIzbW1tNW9sbW5kY2hxMnRoM2Z0cm42OTg2cyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6Ijg1NzZjZGVkLTYyZTEtMTFlOS1iNTI3LWYxYmEzNWEyY2U4MyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTU1NzA1NjM1LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMV95ZXBHRnFTaXUiLCJjb2duaXRvOnVzZXJuYW1lIjoidGVzdFVzZXIiLCJleHAiOjE1NTU3MDkyMzUsImlhdCI6MTU1NTcwNTYzNSwiZW1haWwiOiJsYXJ3ZWZAZ21haWwuY29tIn0.hHpOKjU2Irqi8RdSPotFFP54tyPivFyZI7aLTCdUq-ERkBi_3htYqIgZ1ELspTZAIzUbeQqJ1cipJUBH6vKh-oAV4gQ-OnWrtiErHFmoOoWzX4Ageil6RiJrrYMW1Qk3SXHvbHmXOGL7KGdIYdQXsQ6sNLRFP5kGxB2vVRFj6r-UKLsDeAaa3rZ48tcrH7suRGFJXqyRr9MsYmPpT5Y4QTxAOVupD3kQj0Yuqg_BkgAwnA5V3s-dnloEgnD8f4sVe8hMJ4R8sNAWNGYCiAZvx1p--1-FeTXxCxFSkvUK_H5bUGX8HlrxEpm01mJG0ufmhmMlcE5fLKNMCRPG5b6mQQ"
var invalidSignatureTestToken = "eyJraWQiOiJ5SmdkcHMzM3YxTmc5Tk1pWElDTXhGQU1DOTloMnA3VGxYWkFyMDlZaStvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJjMWI5YWFlMi1iMzliLTQ4MDktODcwMy0zMWUwZTNmOGUyNzkiLCJhdWQiOiIzbW1tNW9sbW5kY2hxMnRoM2Z0cm42OTg2cyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6ImUwMzg5OTMyLTYyZTEtMTFlOS1iNTI3LWYxYmEzNWEyY2U4MyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTU1NzA1Nzg4LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMV95ZXBHRnFTaXUiLCJjb2duaXRvOnVzZXJuYW1lIjoidXNlciIsImV4cCI6MTU1NTcwOTM4OCwiaWF0IjoxNTU1NzA1Nzg4LCJlbWFpbCI6ImxhcndlZkBnbWFpbC5jb20ifQ.AQbRiAiBLQZmHlmayj7L5a4ZIIWsn9atwUPvMgOo6rGwNbcXMVd937iObIjSclOGhR7UQDikqtESv3FQIYRJ6lkgIHkOmBMLhdgNofaOO4I-qyj73xdRWA42Y9OXHFd-FRC_XlGGqMMCtRxsQ5g-YPQAnYilhKGi72olXcEplcQmR4Qdor6UpwPx0jseduFhCBVA8Sb4yBuixoSviJp-o_hzvuSRULHGCoKRH1z_FC6h721RAh1xT2zWYyIEquQzGReNw1LM12KGnerxgjPntBgrWRchwiVOP4xdXVPSqIlNplEVZqhtjYg1fS-hGNAC5eYIB60Xe52HRN13e3EMFg"

func TestJWTVerifier_getPublicKeys(t *testing.T) {
	serverURL, teardown := issuerMock()
	defer teardown()

	verifier := JWTVerifier{
		Issuer: serverURL,
	}

	if err := verifier.getPublicKeys(); err != nil {
		t.Errorf("getPublicKeys returned an error: %v", err)
	}

	if len(verifier.keys) != 2 {
		t.Errorf("unexpected number of keys %d", len(verifier.keys))
	}

	key1, exists := verifier.keys["yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o="]
	if !exists {
		t.Error("coulnd't find key with kid: yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o=")
	}

	if key1.Alg != "RS256" {
		t.Error("unexpected alg for key1")
	}

	if key1.Use != "sig" {
		t.Error("unexpected sig for key1")
	}

	if key1.pubKey == nil {
		t.Error("field pubKey for key1 is nil. Expected non nil")
	}

	key2, exists := verifier.keys["2aix/O2WkwHkngMLTkGZi8QBqpi7co13j1JpRomVAus="]
	if !exists {
		t.Error("coulnd't find key with kid: 2aix/O2WkwHkngMLTkGZi8QBqpi7co13j1JpRomVAus=")
	}

	if key2.Alg != "RS256" {
		t.Error("unexpected alg for key2")
	}

	if key2.Use != "sig" {
		t.Error("unexpected sig for key2")
	}

	if key2.pubKey == nil {
		t.Error("field pubKey for key2 is nil. Expected non nil")
	}
}

func TestJWTVerifier_Parse(t *testing.T) {
	verifier := JWTVerifier{
		Issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_yepGFqSiu",
		keys:   make(map[string]key),
	}

	verifier.keys["yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o="] = key{
		Alg:    "RS256",
		E:      "AQAB",
		Kid:    "yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o=",
		Kty:    "RSA",
		N:      "p0sqs8Q0a9RidBEjO43r50wejpWb9EllsLIGqKg6hjBplzCNNVZD6OK8xU9-S5MYRwsoa-jsL53TX0M728XfsnZrhhfY4FS28ManKb6KUREzj31lqTRLq4eujuL99qfvur47ZVjxlz2NiRlf15c8wlXnluzbK1ppOCaTcBXZNDFDNShopqobmN5rj0xzgeQ1R7_trsrwg69nawpY9sSQ70PVjB5HUWiUSyUR9Nf03yw68Xa7X_xVnyWGHF4aeKlA2qLmrAG7JOiBFt06U-oBDrAh0wr2JaGzMqh_rQPvSQ_UXw5MbgGLPdHzED76LgFonURMHNT3z14DAvUf4fKoTQ",
		Use:    "sig",
		pubKey: getPublicKey(),
	}

	_, err := verifier.parse(validSignatureTestToken, time.Unix(1555709234, 0))
	if err != nil {
		t.Errorf("parse returned an error: %v", err)
	}

	_, err = verifier.parse("Bearer "+validSignatureTestToken, time.Unix(1555709234, 0))
	if err != nil {
		t.Errorf("parse returned an error: %v", err)
	}
}

func TestJWTVerifier_Parse_NonMatchingIssuer(t *testing.T) {
	verifier := JWTVerifier{
		Issuer: "SomeOtherIssuer",
		keys:   make(map[string]key),
	}

	verifier.keys["yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o="] = key{
		Alg:    "RS256",
		E:      "AQAB",
		Kid:    "yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o=",
		Kty:    "RSA",
		N:      "p0sqs8Q0a9RidBEjO43r50wejpWb9EllsLIGqKg6hjBplzCNNVZD6OK8xU9-S5MYRwsoa-jsL53TX0M728XfsnZrhhfY4FS28ManKb6KUREzj31lqTRLq4eujuL99qfvur47ZVjxlz2NiRlf15c8wlXnluzbK1ppOCaTcBXZNDFDNShopqobmN5rj0xzgeQ1R7_trsrwg69nawpY9sSQ70PVjB5HUWiUSyUR9Nf03yw68Xa7X_xVnyWGHF4aeKlA2qLmrAG7JOiBFt06U-oBDrAh0wr2JaGzMqh_rQPvSQ_UXw5MbgGLPdHzED76LgFonURMHNT3z14DAvUf4fKoTQ",
		Use:    "sig",
		pubKey: getPublicKey(),
	}

	_, err := verifier.parse(validSignatureTestToken, time.Unix(1555709234, 0))
	if err != ErrIssuerDoesntMatch {
		t.Errorf("expected Parse to return error: %v but got: %v", ErrIssuerDoesntMatch, err)
	}
}

func TestJWTVerifier_Parse_TokenExpired(t *testing.T) {
	verifier := JWTVerifier{
		Issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_yepGFqSiu",
		keys:   make(map[string]key),
	}

	verifier.keys["yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o="] = key{
		Alg:    "RS256",
		E:      "AQAB",
		Kid:    "yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o=",
		Kty:    "RSA",
		N:      "p0sqs8Q0a9RidBEjO43r50wejpWb9EllsLIGqKg6hjBplzCNNVZD6OK8xU9-S5MYRwsoa-jsL53TX0M728XfsnZrhhfY4FS28ManKb6KUREzj31lqTRLq4eujuL99qfvur47ZVjxlz2NiRlf15c8wlXnluzbK1ppOCaTcBXZNDFDNShopqobmN5rj0xzgeQ1R7_trsrwg69nawpY9sSQ70PVjB5HUWiUSyUR9Nf03yw68Xa7X_xVnyWGHF4aeKlA2qLmrAG7JOiBFt06U-oBDrAh0wr2JaGzMqh_rQPvSQ_UXw5MbgGLPdHzED76LgFonURMHNT3z14DAvUf4fKoTQ",
		Use:    "sig",
		pubKey: getPublicKey(),
	}

	_, err := verifier.parse(validSignatureTestToken, time.Unix(1555709236, 0))
	if err != ErrTokenExpired {
		t.Errorf("expected Parse to return error: %v but got: %v", ErrTokenExpired, err)
	}
}

func TestJWTVerifier_Parse_InvalidSignature(t *testing.T) {
	verifier := JWTVerifier{
		Issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_yepGFqSiu",
		keys:   make(map[string]key),
	}

	verifier.keys["yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o="] = key{
		Alg:    "RS256",
		E:      "AQAB",
		Kid:    "yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o=",
		Kty:    "RSA",
		N:      "p0sqs8Q0a9RidBEjO43r50wejpWb9EllsLIGqKg6hjBplzCNNVZD6OK8xU9-S5MYRwsoa-jsL53TX0M728XfsnZrhhfY4FS28ManKb6KUREzj31lqTRLq4eujuL99qfvur47ZVjxlz2NiRlf15c8wlXnluzbK1ppOCaTcBXZNDFDNShopqobmN5rj0xzgeQ1R7_trsrwg69nawpY9sSQ70PVjB5HUWiUSyUR9Nf03yw68Xa7X_xVnyWGHF4aeKlA2qLmrAG7JOiBFt06U-oBDrAh0wr2JaGzMqh_rQPvSQ_UXw5MbgGLPdHzED76LgFonURMHNT3z14DAvUf4fKoTQ",
		Use:    "sig",
		pubKey: getPublicKey(),
	}

	_, err := verifier.parse(invalidSignatureTestToken, time.Unix(1555709234, 0))
	if err != ErrInvalidSignature {
		t.Errorf("expected Parse to return error: %v but got: %v", ErrInvalidSignature, err)
	}
}

func TestJWTVerifier_Parse_MissingPublicKey(t *testing.T) {
	verifier := JWTVerifier{
		Issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_yepGFqSiu",
		keys:   make(map[string]key),
	}

	verifier.keys["someKid"] = key{
		Alg:    "RS256",
		E:      "AQAB",
		Kid:    "yJgdps33v1Ng9NMiXICMxFAMC99h2p7TlXZAr09Yi+o=",
		Kty:    "RSA",
		N:      "p0sqs8Q0a9RidBEjO43r50wejpWb9EllsLIGqKg6hjBplzCNNVZD6OK8xU9-S5MYRwsoa-jsL53TX0M728XfsnZrhhfY4FS28ManKb6KUREzj31lqTRLq4eujuL99qfvur47ZVjxlz2NiRlf15c8wlXnluzbK1ppOCaTcBXZNDFDNShopqobmN5rj0xzgeQ1R7_trsrwg69nawpY9sSQ70PVjB5HUWiUSyUR9Nf03yw68Xa7X_xVnyWGHF4aeKlA2qLmrAG7JOiBFt06U-oBDrAh0wr2JaGzMqh_rQPvSQ_UXw5MbgGLPdHzED76LgFonURMHNT3z14DAvUf4fKoTQ",
		Use:    "sig",
		pubKey: getPublicKey(),
	}

	_, err := verifier.parse(validSignatureTestToken, time.Unix(1555709234, 0))
	if err != ErrMissingPublicKey {
		t.Errorf("expected Parse to return error: %v but got: %v", ErrMissingPublicKey, err)
	}
}

func issuerMock() (serverURL string, teardown func()) {
	mux := http.NewServeMux()

	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadFile("../test/testdata/jwks.json")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Fprint(w, string(b))
	})

	server := httptest.NewServer(apiHandler)

	return server.URL, server.Close
}

func getPublicKey() *rsa.PublicKey {
	n, _ := big.NewInt(0).SetString("21118863062606400771388931486908742150232765273454857875243927019669623115371292816520129519009603183019096026875790110878113723164336644315241435228676958547624129348566299367642181772531781440654080366042347838474299628672891855257425194205416230654743259092040669189945563025547766952609391002833086073865767976282952972460180034452598004932602735427736519675360048405715167933490034530954429955131064329267441237818320755666694033048428791420312904958627815927038605966790833275281774962474635177090090798490014739136070145422069449600979985195816262423478719472342971156920043550334606637736612831679946968705101", 10)
	e, _ := big.NewInt(0).SetString("65537", 10)
	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
}
