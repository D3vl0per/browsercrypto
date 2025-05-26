package browsercrypto_test

import (
	"testing"

	"github.com/D3vl0per/browsercrypto"
	r "github.com/stretchr/testify/require"
)

var ed25519pkstr = `{
    "crv": "Ed25519",
    "ext": true,
    "key_ops": [
      "verify"
    ],
    "kty": "OKP",
    "x": "rLCsH8ZNALLmnqTFiE3zm38Qj7-u2KBTxm8XWQtXqF8"
  }
`
var ed25519skstr = `{
  "crv": "Ed25519",
  "d": "29X54ZStcJS3A_L2Pf0H0MOpkFB9lpxhs5L7BXd3hjQ",
  "ext": true,
  "key_ops": [
    "sign"
  ],
  "kty": "OKP",
  "x": "rLCsH8ZNALLmnqTFiE3zm38Qj7-u2KBTxm8XWQtXqF8"
}
`

var testsign = []byte("DnB all night")

func TestEd25519PrivateJWK(t *testing.T) {
	var pk browsercrypto.PrivateKey
	err := pk.UnmarshalJSON([]byte(ed25519skstr))
	r.NoError(t, err)

	r.Equal(t, "Ed25519", pk.Crv)
	r.Equal(t, "29X54ZStcJS3A_L2Pf0H0MOpkFB9lpxhs5L7BXd3hjQ", pk.D)
	r.True(t, pk.Ext)
	r.Equal(t, []string{"sign"}, pk.KeyOps)
	r.Equal(t, "OKP", pk.Kty)
	r.Equal(t, "rLCsH8ZNALLmnqTFiE3zm38Qj7-u2KBTxm8XWQtXqF8", pk.X)
}

func TestEd25519PublicJWK(t *testing.T) {
	var pk browsercrypto.PublicKey
	err := pk.UnmarshalJSON([]byte(ed25519pkstr))
	r.NoError(t, err)

	r.Equal(t, "Ed25519", pk.Crv)
	r.True(t, pk.Ext)
	r.Equal(t, []string{"verify"}, pk.KeyOps)
	r.Equal(t, "OKP", pk.Kty)
	r.Equal(t, "rLCsH8ZNALLmnqTFiE3zm38Qj7-u2KBTxm8XWQtXqF8", pk.X)
}

func TestSignVerify(t *testing.T) {
	var sk browsercrypto.PrivateKey
	err := sk.UnmarshalJSON([]byte(ed25519skstr))
	r.NoError(t, err)

	var pk browsercrypto.PublicKey
	err = pk.UnmarshalJSON([]byte(ed25519pkstr))
	r.NoError(t, err)

	signature, err := browsercrypto.Sign(&sk, testsign)
	r.NoError(t, err)
	r.NotEmpty(t, signature)
	t.Log("Signature: ", signature)

	verified, err := browsercrypto.Verify(&pk, signature, testsign)
	r.NoError(t, err)
	r.True(t, verified)
}
