package passtrail

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

// create a deterministic test pass
func makeTestPass(n int) (*Pass, error) {
	txs := make([]*Consideration, n)

	// create txs
	for i := 0; i < n; i++ {
		// create a sender
		seed := strings.Repeat(strconv.Itoa(i%10), ed25519.SeedSize)
		privKey := ed25519.NewKeyFromSeed([]byte(seed))
		pubKey := privKey.Public().(ed25519.PublicKey)

		// create a recipient
		seed2 := strings.Repeat(strconv.Itoa((i+1)%10), ed25519.SeedSize)
		privKey2 := ed25519.NewKeyFromSeed([]byte(seed2))
		pubKey2 := privKey2.Public().(ed25519.PublicKey)

		matures := MAX_NUMBER
		expires := MAX_NUMBER
		height := MAX_NUMBER

		tx := NewConsideration(pubKey, pubKey2, matures, height, expires, "こんにちは")
		if len(tx.Memo) != 15 {
			// make sure len() gives us bytes not rune count
			return nil, fmt.Errorf("Expected memo length to be 15 but received %d", len(tx.Memo))
		}
		tx.Nonce = int32(123456789 + i)

		// sign the consideration
		if err := tx.Sign(privKey); err != nil {
			return nil, err
		}
		txs[i] = tx
	}

	// create the pass
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		return nil, err
	}
	var target PassID
	copy(target[:], targetBytes)
	pass, err := NewPass(PassID{}, 0, target, PassID{}, txs)
	if err != nil {
		return nil, err
	}
	return pass, nil
}

func TestPassHeaderHasher(t *testing.T) {
	pass, err := makeTestPass(10)
	if err != nil {
		t.Fatal(err)
	}

	if !compareIDs(pass) {
		t.Fatal("ID mismatch 1")
	}

	pass.Header.Time = 1234

	if !compareIDs(pass) {
		t.Fatal("ID mismatch 2")
	}

	pass.Header.Nonce = 1234

	if !compareIDs(pass) {
		t.Fatal("ID mismatch 3")
	}

	pass.Header.Nonce = 1235

	if !compareIDs(pass) {
		t.Fatal("ID mismatch 4")
	}

	pass.Header.Nonce = 1236
	pass.Header.Time = 1234

	if !compareIDs(pass) {
		t.Fatal("ID mismatch 5")
	}

	pass.Header.Time = 123498
	pass.Header.Nonce = 12370910

	txID, _ := pass.Considerations[0].ID()
	if err := pass.AddConsideration(txID, pass.Considerations[0]); err != nil {
		t.Fatal(err)
	}

	if !compareIDs(pass) {
		t.Fatal("ID mismatch 6")
	}

	pass.Header.Time = 987654321

	if !compareIDs(pass) {
		t.Fatal("ID mismatch 7")
	}
}

func compareIDs(pass *Pass) bool {
	// compute header ID
	id, _ := pass.ID()

	// use delta method
	idInt, _ := pass.Header.IDFast(0)
	id2 := new(PassID).SetBigInt(idInt)
	return id == *id2
}
