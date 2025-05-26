package browsercrypto

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/curve25519"
)

type JWKKeyType string

var (
	Ed25519 JWKKeyType = "Ed25519"
	X25519  JWKKeyType = "X25519"

	ErrPrivateKeyAlreadyGenerated = errors.New("private key generation: private key already generated")
	ErrPublicKeyAlreadyGenerated  = errors.New("public key generation: public key already generated")
	ErrUnsupportedCurve           = errors.New("unsupported curve type")
	ErrPrivateKeyTooShort         = errors.New("private key loading: private key is too short")
	ErrPublicKeyTooShort          = errors.New("public key loading: public key is too short")
	ErrNotTypeEd25519PublicKey    = errors.New("private key generation: public key is not of type ed25519.PublicKey")
)

type JWKPrivate interface {
	PrivateKey() ([]byte, error)
	PublicKey() ([]byte, error)
	UnmarshalJSON(data []byte) error
	GetCrv() string
	GetKty() string
	GetKeyOps() []string
	GenerateKey(JWKKeyType) error
}

type JWKPublic interface {
	UnmarshalJSON(data []byte) error
	PublicKey() ([]byte, error)
	GetCrv() string
	GetKty() string
	GetKeyOps() []string
	GenerateKey(JWKKeyType) error
}

type PrivateKey struct {
	Crv    string   `json:"crv"`
	D      string   `json:"d"`
	Kty    string   `json:"kty"`
	X      string   `json:"x"`
	KeyOps []string `json:"key_ops"`
	Ext    bool     `json:"ext"`
}

func (p *PrivateKey) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("private key loading: private key is empty")
	}

	type A PrivateKey
	var a A
	err := json.Unmarshal(data, &a)
	if err != nil {
		return err
	}

	if a.D == "" {
		return errors.New("private key loading: private key D components is empty")
	}

	*p = PrivateKey(a)
	return nil
}

func (p *PrivateKey) PublicKey() ([]byte, error) {
	if p.X == "" {
		return nil, errors.New("public key generation: public key X component is empty")
	}
	return JWKBase64Decode(p.X)
}

func (p *PrivateKey) PrivateKey() ([]byte, error) {
	if p.D == "" {
		return nil, errors.New("public key generation: public key X component is empty")
	}

	switch p.Crv {
	case "Ed25519":
		sk, err := JWKBase64Decode(p.D)
		if err != nil {
			return nil, err
		}

		return ed25519.NewKeyFromSeed(sk), nil

	case "X25519":
		return JWKBase64Decode(p.D)
	}
	return nil, ErrUnsupportedCurve
}

func (p *PrivateKey) GetCrv() string {
	return p.Crv
}

func (p *PrivateKey) GetKty() string {
	return p.Kty
}

func (p *PrivateKey) GetKeyOps() []string {
	return p.KeyOps
}

func (p *PrivateKey) GenerateKey(keyType JWKKeyType) error {
	if p.D != "" {
		return ErrPrivateKeyAlreadyGenerated
	}

	switch keyType {
	case Ed25519:
		d, err := generic.CSPRNG(32)
		if err != nil {
			return err
		}

		x := ed25519.NewKeyFromSeed(d)

		p.D = JWKBase64Encode(x)
		p.X = JWKBase64Encode(d)
		p.KeyOps = []string{"sign"}
		p.Crv = "Ed25519"
		p.Kty = "OKP"
		p.Ext = true

	case X25519:
		d, err := generic.CSPRNG(curve25519.PointSize)
		if err != nil {
			return err
		}

		x, err := curve25519.X25519(d, curve25519.Basepoint)
		if err != nil {
			return err
		}

		p.D = JWKBase64Encode(d)
		p.X = JWKBase64Encode(x)
		p.KeyOps = []string{"deriveKey", "deriveBits"}
		p.Crv = "X25519"
		p.Kty = "OKP"
		p.Ext = true
	default:
		return ErrUnsupportedCurve
	}

	return nil
}

func LoadX25519PrivateJWK(d string) (PrivateKey, error) {
	var pk PrivateKey

	pk.D = d
	pk.Crv = "X25519"
	pk.Ext = true
	pk.KeyOps = []string{"deriveKey"}
	pk.Kty = "OKP"

	sk, err := JWKBase64Decode(pk.D)
	if err != nil {
		return PrivateKey{}, err
	}

	publicKey, err := curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		return PrivateKey{}, err
	}
	pk.X = JWKBase64Encode(publicKey)

	return pk, nil
}

func LoadEd25519PrivateJWK(d string) (PrivateKey, error) {
	var pk PrivateKey

	pk.D = d
	pk.Crv = "Ed25519"
	pk.Ext = true
	pk.KeyOps = []string{"sign"}
	pk.Kty = "OKP"

	sk, err := JWKBase64Decode(pk.D)
	if err != nil {
		return PrivateKey{}, err
	}

	publicKey, ok := ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)
	if !ok {
		return PrivateKey{}, ErrNotTypeEd25519PublicKey
	}

	pk.X = JWKBase64Encode(publicKey)

	return pk, nil
}

func LoadX25519PrivateRaw(sk []byte) (PrivateKey, error) {
	if len(sk) != 32 {
		return PrivateKey{}, ErrPrivateKeyTooShort
	}

	var pk PrivateKey
	pk.D = JWKBase64Encode(sk)

	x, err := curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		return PrivateKey{}, err
	}

	pk.X = JWKBase64Encode(x)
	pk.Crv = "X25519"
	pk.KeyOps = []string{"deriveKey", "deriveBits"}
	pk.Kty = "OKP"
	pk.Ext = true

	return pk, nil
}

func LoadEd25519PrivateRaw(sk []byte) (PrivateKey, error) {
	if len(sk) != 32 {
		return PrivateKey{}, ErrPrivateKeyTooShort
	}

	var pk PrivateKey
	pk.D = JWKBase64Encode(sk)

	x, ok := ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)
	if !ok {
		return PrivateKey{}, ErrNotTypeEd25519PublicKey
	}

	pk.X = JWKBase64Encode(x)
	pk.Crv = "Ed25519"
	pk.KeyOps = []string{"sign"}
	pk.Kty = "OKP"
	pk.Ext = true

	return pk, nil
}

type PublicKey struct {
	Crv    string   `json:"crv"`
	Kty    string   `json:"kty"`
	X      string   `json:"x"`
	KeyOps []string `json:"key_ops"`
	Ext    bool     `json:"ext"`
}

func (p *PublicKey) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("private key loading: private key is empty")
	}
	type A PublicKey
	var a A
	err := json.Unmarshal(data, &a)
	if err != nil {
		return err
	}
	*p = PublicKey(a)
	return nil
}

func (p *PublicKey) PublicKey() ([]byte, error) {
	if p.X == "" {
		return nil, errors.New("public key generation: public key X component is empty")
	}
	return JWKBase64Decode(p.X)
}

func (p *PublicKey) GetCrv() string {
	return p.Crv
}

func (p *PublicKey) GetKty() string {
	return p.Kty
}

func (p *PublicKey) GetKeyOps() []string {
	return p.KeyOps
}

func (p *PublicKey) GenerateKey(keyType JWKKeyType) error {
	if p.X != "" {
		return ErrPublicKeyAlreadyGenerated
	}
	switch keyType {
	case Ed25519:
		d, err := generic.CSPRNG(32)
		if err != nil {
			return err
		}
		x := ed25519.NewKeyFromSeed(d)
		p.X = JWKBase64Encode(x)
		p.KeyOps = []string{"verify"}
		p.Crv = "Ed25519"
		p.Kty = "OKP"
		p.Ext = true

	case X25519:
		d, err := generic.CSPRNG(curve25519.PointSize)
		if err != nil {
			return err
		}

		x, err := curve25519.X25519(d, curve25519.Basepoint)
		if err != nil {
			return err
		}

		p.X = JWKBase64Encode(x)
		p.KeyOps = []string{}
		p.Crv = "X25519"
		p.Kty = "OKP"
		p.Ext = true
	default:
		return ErrUnsupportedCurve
	}

	return nil
}

func LoadX25519PublicJWK(x string) (PublicKey, error) {
	var pk PublicKey

	pk.X = x
	pk.Crv = "X25519"
	pk.Ext = true
	pk.Kty = "OKP"

	return pk, nil
}

func LoadEd25519PublicJWK(x string) (PublicKey, error) {
	var pk PublicKey

	pk.X = x
	pk.Crv = "Ed25519"
	pk.Ext = true
	pk.Kty = "OKP"
	pk.KeyOps = []string{"verify"}

	return pk, nil
}

func LoadX25519PublicRaw(pk []byte) (PublicKey, error) {
	if len(pk) != 32 {
		return PublicKey{}, ErrPublicKeyTooShort
	}

	var p PublicKey
	p.X = JWKBase64Encode(pk)
	p.Crv = "X25519"
	p.KeyOps = []string{}
	p.Kty = "OKP"
	p.Ext = true

	return p, nil
}

func LoadEd25519PublicRaw(pk []byte) (PublicKey, error) {
	if len(pk) != 32 {
		return PublicKey{}, ErrPublicKeyTooShort
	}

	var p PublicKey
	p.X = JWKBase64Encode(pk)
	p.Crv = "Ed25519"
	p.KeyOps = []string{"verify"}
	p.Kty = "OKP"
	p.Ext = true

	return p, nil
}
