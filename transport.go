package cognito

import (
	"net/http"
)

type transport struct {
	tknSrc *TokenSource
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, nil
}
