package passtrail

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestEncodePassHeader(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// create a passpoint
	tx := NewConsideration(nil, pubKey, 0, 0, 0, "hello")

	// create a pass
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		t.Fatal(err)
	}
	var target PassID
	copy(target[:], targetBytes)
	pass, err := NewPass(PassID{}, 0, target, PassID{}, []*Consideration{tx})
	if err != nil {
		t.Fatal(err)
	}

	// encode the header
	encodedHeader, err := encodePassHeader(pass.Header, 12345)
	if err != nil {
		t.Fatal(err)
	}

	// decode the header
	header, when, err := decodePassHeader(encodedHeader)
	if err != nil {
		t.Fatal(err)
	}

	// compare
	if *header != *pass.Header {
		t.Fatal("Decoded header doesn't match original")
	}

	if when != 12345 {
		t.Fatal("Decoded timestamp doesn't match original")
	}
}
