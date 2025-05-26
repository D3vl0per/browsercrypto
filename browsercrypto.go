package browsercrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/D3vl0per/crypt/compression"
	"github.com/D3vl0per/crypt/symmetric"
	"golang.org/x/crypto/curve25519"
)

var (
	ErrDifferentCurves     = errors.New("private and public keys have different curves")
	ErrCurveIsNil          = errors.New("curve is empty")
	ErrCurveIsNotSupported = errors.New("curve is not supported")
	ErrCipherIsNil         = errors.New("cipher is nil")
)

func Uint8ArrayToByteArray(array string) ([]byte, error) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(array), &data)
	if err != nil {
		return nil, err
	}

	byteArray := make([]byte, len(data))
	keys := make([]int, 0, len(data))

	for key := range data {
		k, err := strconv.Atoi(key)
		if err != nil {
			return nil, errors.Join(errors.New("Uint8ArrayToByteArray: "), err)
		}
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, key := range keys {
		v, ok := data[strconv.Itoa(key)].(float64)
		if !ok {
			return nil, errors.Join(errors.New("Uint8ArrayToByteArray: "), errors.New("value is not a float64"))
		}
		byteArray[key] = byte(v)
	}

	return byteArray, nil
}

func ByteArrayToUint8Array(array []byte) (string, error) {
	data := make(map[string]int, len(array))

	for i, v := range array {
		data[strconv.Itoa(i)] = int(v)
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func DeriveKey(pk JWKPublic, sk JWKPrivate) ([]byte, error) {
	if pk.GetCrv() == "" || sk.GetCrv() == "" {
		return nil, ErrCurveIsNil
	}
	if pk.GetCrv() != sk.GetCrv() {
		return nil, ErrDifferentCurves
	}

	rawPk, err := pk.PublicKey()
	if err != nil {
		return nil, err
	}

	rawSk, err := sk.PrivateKey()
	if err != nil {
		return nil, err
	}

	switch pk.GetCrv() {
	case "X25519":
		return curve25519.X25519(rawSk, rawPk)
	default:
		return nil, ErrCurveIsNotSupported
	}
}

func Sign(sk JWKPrivate, data []byte) ([]byte, error) {

	if sk.GetCrv() == "" {
		return nil, ErrCurveIsNil
	}

	if sk.GetCrv() != "Ed25519" {
		return nil, ErrCurveIsNotSupported
	}

	rawSk, err := sk.PrivateKey()
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(ed25519.PrivateKey(rawSk), data), nil
}

func Verify(pk JWKPublic, signature []byte, data []byte) (bool, error) {

	if pk.GetCrv() == "" {
		return false, ErrCurveIsNil
	}

	if pk.GetCrv() != "Ed25519" {
		return false, ErrCurveIsNotSupported
	}

	rawPk, err := pk.PublicKey()
	if err != nil {
		return false, err
	}

	return ed25519.Verify(ed25519.PublicKey(rawPk), data, signature), nil
}

func JWKBase64Decode(payload string) ([]byte, error) {
	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	return base64.StdEncoding.DecodeString(payload)
}

func JWKBase64Encode(payload []byte) string {
	return base64.StdEncoding.EncodeToString(payload)
}

func Encrypt(pk JWKPublic, sk JWKPrivate, plaintext []byte, cipher symmetric.Symmetric) ([]byte, error) {
	if cipher == nil {
		return nil, ErrCipherIsNil
	}

	cs, err := DeriveKey(pk, sk)
	if err != nil {
		return nil, err
	}

	plaintextArray, err := ByteArrayToUint8Array(plaintext)
	if err != nil {
		return nil, err
	}

	ciphertext, err := cipher.Encrypt(cs, []byte(plaintextArray))
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func Decrypt(pk JWKPublic, sk JWKPrivate, ciphertext []byte, cipher symmetric.Symmetric) ([]byte, error) {
	cs, err := DeriveKey(pk, sk)
	if err != nil {
		return nil, err
	}

	plaintextArray, err := cipher.Decrypt(cs, ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, err := Uint8ArrayToByteArray(string(plaintextArray))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DecryptAndDecompress(pk JWKPublic, sk JWKPrivate, ciphertext []byte, cipher symmetric.Symmetric) ([]byte, error) {

	cs, err := DeriveKey(pk, sk)
	if err != nil {
		return nil, err
	}

	plaintextArray, err := cipher.Decrypt(cs, ciphertext)
	if err != nil {
		return nil, err
	}

	compressed, err := Uint8ArrayToByteArray(string(plaintextArray))
	if err != nil {
		return nil, err
	}

	compressor := compression.Gzip{}

	plaintext, err := compressor.Decompress(compressed)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
