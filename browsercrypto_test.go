package browsercrypto_test

import (
	"testing"

	"github.com/D3vl0per/browsercrypto"
	r "github.com/stretchr/testify/require"
)

var testArray = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}

func TestArrayConvert(t *testing.T) {

	payload, err := browsercrypto.ByteArrayToUint8Array(testArray)
	r.NoError(t, err)

	array, err := browsercrypto.Uint8ArrayToByteArray(payload)
	r.NoError(t, err)
	r.Equal(t, testArray, array)

}
