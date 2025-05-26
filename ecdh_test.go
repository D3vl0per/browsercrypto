package browsercrypto_test

import (
	"testing"

	"github.com/D3vl0per/browsercrypto"
	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/symmetric"
	r "github.com/stretchr/testify/require"

	"golang.org/x/crypto/curve25519"
)

var pkstr = `{
		"crv": "X25519",
		"ext": true,
		"key_ops": [],
		"kty": "OKP",
		"x": "qFjYM8FqK7sdYTuLEBTSWjG2SZDxQKcMsqmzah6F2yY"
	}`
var skstr = `{
		"crv": "X25519",
		"d": "jzWuYVkUt2fhXQyB10eGdhkyu6T0mO8QmElTBQ4UQ70",
		"ext": true,
		"key_ops": [
			"deriveKey"
		],
		"kty": "OKP",
		"x": "qFjYM8FqK7sdYTuLEBTSWjG2SZDxQKcMsqmzah6F2yY"
	}`

var derivedKey = "b10c210b0f7519b9331638d38c451b7175b2e47263791e55c765e77cf0b0a714"

var encoder = generic.Hex{}

var plaintext = []byte("Boiler room")

func TestPrivateJWK(t *testing.T) {
	var pk browsercrypto.PrivateKey
	err := pk.UnmarshalJSON([]byte(skstr))
	r.NoError(t, err)

	r.Equal(t, "X25519", pk.Crv)
	r.Equal(t, "jzWuYVkUt2fhXQyB10eGdhkyu6T0mO8QmElTBQ4UQ70", pk.D)
	r.True(t, pk.Ext)
	r.Equal(t, []string{"deriveKey"}, pk.KeyOps)
	r.Equal(t, "OKP", pk.Kty)
	r.Equal(t, "qFjYM8FqK7sdYTuLEBTSWjG2SZDxQKcMsqmzah6F2yY", pk.X)
}

func TestPublicJWK(t *testing.T) {

	var pk browsercrypto.PublicKey
	err := pk.UnmarshalJSON([]byte(pkstr))
	r.NoError(t, err)

	r.Equal(t, "X25519", pk.Crv)
	r.True(t, pk.Ext)
	r.Equal(t, []string{}, pk.KeyOps)
	r.Equal(t, "OKP", pk.Kty)
	r.Equal(t, "qFjYM8FqK7sdYTuLEBTSWjG2SZDxQKcMsqmzah6F2yY", pk.X)
}

func TestDeriveKey(t *testing.T) {
	var secretKey browsercrypto.PrivateKey
	err := secretKey.UnmarshalJSON([]byte(skstr))
	r.NoError(t, err)

	var publicKey browsercrypto.PublicKey
	err = publicKey.UnmarshalJSON([]byte(pkstr))
	r.NoError(t, err)

	goPublicKey, err := publicKey.PublicKey()
	r.NoError(t, err)

	goSecretKey, err := secretKey.PrivateKey()
	r.NoError(t, err)

	sharedSecret, err := curve25519.X25519(goSecretKey, goPublicKey)
	r.NoError(t, err)
	t.Log("Shared secret", sharedSecret)
	sharedKeyHex := encoder.Encode(sharedSecret)
	t.Log("Shared key hex", sharedKeyHex)
	r.Equal(t, derivedKey, sharedKeyHex)
}

func TestEncryptDecrypt(t *testing.T) {
	var secretKey browsercrypto.PrivateKey
	err := secretKey.UnmarshalJSON([]byte(skstr))
	r.NoError(t, err)

	var publicKey browsercrypto.PublicKey
	err = publicKey.UnmarshalJSON([]byte(pkstr))
	r.NoError(t, err)

	ciphertext, err := browsercrypto.Encrypt(&publicKey, &secretKey, plaintext, &symmetric.AesGCM{})
	r.NoError(t, err)

	decryptedPlaintext, err := browsercrypto.Decrypt(&publicKey, &secretKey, ciphertext, &symmetric.AesGCM{})
	r.NoError(t, err)
	r.Equal(t, plaintext, decryptedPlaintext)
}
