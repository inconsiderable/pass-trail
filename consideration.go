package passtrail

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// Consideration represents a ledger consideration. It transfers value from one public key to another.
type Consideration struct {//TODO: Beware of reordering struct fields, IDs seem to be sensitive to field order.
	Time      int64             `json:"time"`
	Nonce     int32             `json:"nonce"` // collision prevention. pseudorandom. not used for crypto
	By        ed25519.PublicKey `json:"by,omitempty"`
	For       ed25519.PublicKey `json:"for"`
	Memo      string            `json:"memo,omitempty"`    // max 100 characters
	Matures   int64             `json:"matures,omitempty"` // pass height. if set consideration can't be trailed before
	Expires   int64             `json:"expires,omitempty"` // pass height. if set consideration can't be trailed after
	Series    int64             `json:"series"`            // +1 roughly once a week to allow for pruning history
	Signature Signature         `json:"signature,omitempty"`
}

// ConsiderationID is a consideration's unique identifier.
type ConsiderationID [32]byte // SHA3-256 hash

// Signature is a consideration's signature.
type Signature []byte

// NewConsideration returns a new unsigned consideration.
func NewConsideration(by, forr ed25519.PublicKey, matures, expires, height int64, memo string) *Consideration {
	return &Consideration{
		Time:    time.Now().Unix(),
		Nonce:   rand.Int31(),
		By:      by,
		For:     forr,
		Memo:    memo,
		Matures: matures,
		Expires: expires,
		Series:  computeConsiderationSeries(by == nil, height),
	}
}

// ID computes an ID for a given consideration.
func (tx Consideration) ID() (ConsiderationID, error) {
	// never include the signature in the ID
	// this way we never have to think about signature malleability
	tx.Signature = nil
	txJson, err := json.Marshal(tx)
	if err != nil {
		return ConsiderationID{}, err
	}
	return sha3.Sum256([]byte(txJson)), nil
}

// Sign is called to sign a consideration.
func (tx *Consideration) Sign(privKey ed25519.PrivateKey) error {
	id, err := tx.ID()
	if err != nil {
		return err
	}
	tx.Signature = ed25519.Sign(privKey, id[:])
	return nil
}

// Verify is called to verify only that the consideration is properly signed.
func (tx Consideration) Verify() (bool, error) {
	id, err := tx.ID()
	if err != nil {
		return false, err
	}
	return ed25519.Verify(tx.By, id[:], tx.Signature), nil
}

// IsPasspoint returns true if the consideration is a passpoint. A passpoint is the first consideration in every pass
// used to recognise the trailer for trailing the pass.
func (tx Consideration) IsPasspoint() bool {
	return tx.By == nil
}

// Contains returns true if the consideration is relevant to the given public key.
func (tx Consideration) Contains(pubKey ed25519.PublicKey) bool {
	if !tx.IsPasspoint() {
		if bytes.Equal(pubKey, tx.By) {
			return true
		}
	}
	return bytes.Equal(pubKey, tx.For)
}

// IsMature returns true if the consideration can be trailed at the given height.
func (tx Consideration) IsMature(height int64) bool {
	if tx.Matures == 0 {
		return true
	}
	return tx.Matures >= height
}

// IsExpired returns true if the consideration cannot be trailed at the given height.
func (tx Consideration) IsExpired(height int64) bool {
	if tx.Expires == 0 {
		return false
	}
	return tx.Expires < height
}

// String implements the Stringer interface.
func (id ConsiderationID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalJSON marshals ConsiderationID as a hex string.
func (id ConsiderationID) MarshalJSON() ([]byte, error) {
	s := "\"" + id.String() + "\""
	return []byte(s), nil
}

// UnmarshalJSON unmarshals a hex string to ConsiderationID.
func (id *ConsiderationID) UnmarshalJSON(b []byte) error {
	if len(b) != 64+2 {
		return fmt.Errorf("Invalid consideration ID")
	}
	idBytes, err := hex.DecodeString(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	copy(id[:], idBytes)
	return nil
}

// Compute the series to use for a new consideration.
func computeConsiderationSeries(isPasspoint bool, height int64) int64 {
	if isPasspoint {
		// passpoints start using the new series right on time
		return height/PASSES_UNTIL_NEW_SERIES + 1
	}

	// otherwise don't start using a new series until 100 passes in to mitigate
	// potential reorg issues right around the switchover
	return (height-100)/PASSES_UNTIL_NEW_SERIES + 1
}
