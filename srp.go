package cognito

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const (
	nHex           = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
	nBits          = 3072
	gHex           = "2"
	derivedKeyInfo = "Caldera Derived Key"
	derivedKeySize = 16
	h              = crypto.SHA256
)

type srp struct {
	xN *big.Int
	g  *big.Int
	k  *big.Int
	a  *big.Int
	xA *big.Int
}

func newSrp() (*srp, error) {
	s := &srp{}
	var ok bool
	if s.xN, ok = big.NewInt(0).SetString(nHex, 16); !ok {
		return nil, fmt.Errorf("error parsing nHex to big.Int. nHex: %s", nHex)
	}
	if s.g, ok = big.NewInt(0).SetString(gHex, 16); !ok {
		return nil, fmt.Errorf("error parsing gHex to big.Int. gHex: %s", gHex)
	}

	str, err := hex.DecodeString("00" + nHex + "0" + gHex)
	if err != nil {
		return nil, fmt.Errorf("error cmputing k value: %v", err)
	}

	s.k = big.NewInt(0).SetBytes(hash(str))
	s.a = s.generatePrivateKey()
	s.xA = big.NewInt(0).Exp(s.g, s.a, s.xN)

	return s, nil
}

func (s *srp) getA() *big.Int {
	return s.xA
}

func (s *srp) getSignature(userpoolName, username, password, timestamp string, salt, xB *big.Int, secretBlock []byte) (string, error) {
	hkdf := s.getKey(userpoolName, username, password, xB, salt)
	mac := hmac.New(h.New, hkdf)
	mac.Write([]byte(userpoolName))
	mac.Write([]byte(username))
	mac.Write(secretBlock)
	mac.Write([]byte(timestamp))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *srp) generatePrivateKey() *big.Int {
	b := make([]byte, nBits/8)
	rand.Read(b)
	return big.NewInt(0).SetBytes(b)
}

func (s *srp) getKey(userpoolName, username, password string, xB, salt *big.Int) []byte {
	userID := fmt.Sprintf("%s%s:%s", userpoolName, username, password)
	userIDHash := hash([]byte(userID))
	u := big.NewInt(0).SetBytes(hash(pad(s.xA), pad(xB)))
	x := big.NewInt(0).SetBytes(hash(pad(salt), userIDHash))

	t0 := big.NewInt(0).Exp(s.g, x, s.xN)                   // g^x
	t1 := big.NewInt(0).Sub(xB, big.NewInt(0).Mul(s.k, t0)) // B - kg^x
	t2 := big.NewInt(0).Add(s.a, big.NewInt(0).Mul(u, x))   // a + ux
	xS := big.NewInt(0).Exp(t1, t2, s.xN)                   // (B - kg^x)^(a + ux)

	return computeClientEvidenceKey(pad(xS), pad(u))
}

func computeClientEvidenceKey(u, salt []byte) []byte {
	mac := hmac.New(h.New, salt)
	mac.Write(u)
	prk := mac.Sum(nil)

	mac = hmac.New(h.New, prk)
	mac.Write([]byte(derivedKeyInfo))
	mac.Write([]byte{1})
	hmacHash := mac.Sum(nil)
	return hmacHash[:derivedKeySize]
}

func hash(buf ...[]byte) []byte {
	a := h.New()
	for _, elem := range buf {
		a.Write(elem)
	}

	return a.Sum(nil)
}

// TODO: Make version that doesnt use string
func pad(b *big.Int) []byte {
	hexStr := b.Text(16)

	if len(hexStr)%2 == 1 {
		hexStr = fmt.Sprintf("0%s", hexStr)
	} else if strings.Contains("89ABCDEFabcdef", string(hexStr[0])) {
		hexStr = fmt.Sprintf("00%s", hexStr)
	}

	// Shouldnt ignore error. Ignoring until a version of pad with bytes can be made.
	// An erroneous result will result in a failed login. And the chances this will fail are fairly slim.
	res, _ := hex.DecodeString(hexStr)

	return res
}
