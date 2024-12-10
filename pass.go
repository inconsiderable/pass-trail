package passtrail

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"math/rand"
	"time"

	"golang.org/x/crypto/sha3"
)

// Pass represents a pass in the pass trail. It has a header and a list of considerations.
// As passes are connected their considerations affect the underlying ledger.
type Pass struct {
	Header       	*PassHeader   		`json:"header"`
	Considerations 	[]*Consideration 	`json:"considerations"`
	hasher       	hash.Hash      // hash state used by trailer. not marshaled
}

// PassHeader contains data used to determine pass validity and its place in the pass trail.
type PassHeader struct {
	Previous         PassID            `json:"previous"`
	HashListRoot     ConsiderationID      `json:"hash_list_root"`
	Time             int64              `json:"time"`
	Target           PassID            `json:"target"`
	TrailWork        PassID            `json:"trail_work"` // total cumulative trail work
	Nonce            int64              `json:"nonce"`      // not used for crypto
	Height           int64              `json:"height"`
	ConsiderationCount int32              `json:"consideration_count"`
	hasher           *PassHeaderHasher // used to speed up trailing. not marshaled
}

// PassID is a pass's unique identifier.
type PassID [32]byte // SHA3-256 hash

// NewPass creates and returns a new Pass to be trailed.
func NewPass(previous PassID, height int64, target, trailWork PassID, considerations []*Consideration) (
	*Pass, error) {

	// enforce the hard cap consideration limit
	if len(considerations) > MAX_CONSIDERATIONS_PER_PASS {
		return nil, fmt.Errorf("Consideration list size exceeds limit per pass")
	}

	// compute the hash list root
	hasher := sha3.New256()
	hashListRoot, err := computeHashListRoot(hasher, considerations)
	if err != nil {
		return nil, err
	}

	// create the header and pass
	return &Pass{
		Header: &PassHeader{
			Previous:         previous,
			HashListRoot:     hashListRoot,
			Time:             time.Now().Unix(), // just use the system time
			Target:           target,
			TrailWork:        computeTrailWork(target, trailWork),
			Nonce:            rand.Int63n(MAX_NUMBER),
			Height:           height,
			ConsiderationCount: int32(len(considerations)),
		},
		Considerations: considerations,
		hasher:       hasher, // save this to use while trailing
	}, nil
}

// ID computes an ID for a given pass.
func (b Pass) ID() (PassID, error) {
	return b.Header.ID()
}

// CheckPOW verifies the pass's proof-of-work satisfies the declared target.
func (b Pass) CheckPOW(id PassID) bool {
	return id.GetBigInt().Cmp(b.Header.Target.GetBigInt()) <= 0
}

// AddConsideration adds a new consideration to the pass. Called by trailer when trailing a new pass.
func (b *Pass) AddConsideration(id ConsiderationID, tx *Consideration) error {
	// hash the new consideration hash with the running state
	b.hasher.Write(id[:])

	// update the hash list root to account for passpoint amount change
	var err error
	b.Header.HashListRoot, err = addPasspointToHashListRoot(b.hasher, b.Considerations[0])
	if err != nil {
		return err
	}

	// append the new consideration to the list
	b.Considerations = append(b.Considerations, tx)
	b.Header.ConsiderationCount += 1
	return nil
}

// Compute a hash list root of all consideration hashes
func computeHashListRoot(hasher hash.Hash, considerations []*Consideration) (ConsiderationID, error) {
	if hasher == nil {
		hasher = sha3.New256()
	}

	// don't include passpoint in the first round
	for _, tx := range considerations[1:] {
		id, err := tx.ID()
		if err != nil {
			return ConsiderationID{}, err
		}
		hasher.Write(id[:])
	}

	// add the passpoint last
	return addPasspointToHashListRoot(hasher, considerations[0])
}

// Add the passpoint to the hash list root
func addPasspointToHashListRoot(hasher hash.Hash, passpoint *Consideration) (ConsiderationID, error) {
	// get the root of all of the non-passpoint consideration hashes
	rootHashWithoutPasspoint := hasher.Sum(nil)

	// add the passpoint separately
	// this made adding new considerations while trailing more efficient in a financial context
	id, err := passpoint.ID()
	if err != nil {
		return ConsiderationID{}, err
	}

	// hash the passpoint hash with the consideration list root hash
	rootHash := sha3.New256()
	rootHash.Write(id[:])
	rootHash.Write(rootHashWithoutPasspoint[:])

	// we end up with a sort of modified hash list root of the form:
	// HashListRoot = H(TXID[0] | H(TXID[1] | ... | TXID[N-1]))
	var hashListRoot ConsiderationID
	copy(hashListRoot[:], rootHash.Sum(nil))
	return hashListRoot, nil
}

// Compute pass work given its target
func computePassWork(target PassID) *big.Int {
	passWorkInt := big.NewInt(0)
	targetInt := target.GetBigInt()
	if targetInt.Cmp(passWorkInt) <= 0 {
		return passWorkInt
	}
	// pass work = 2**256 / (target+1)
	maxInt := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	targetInt.Add(targetInt, big.NewInt(1))
	return passWorkInt.Div(maxInt, targetInt)
}

// Compute cumulative trail work given a pass's target and the previous trail work
func computeTrailWork(target, trailWork PassID) (newTrailWork PassID) {
	passWorkInt := computePassWork(target)
	trailWorkInt := trailWork.GetBigInt()
	trailWorkInt = trailWorkInt.Add(trailWorkInt, passWorkInt)
	newTrailWork.SetBigInt(trailWorkInt)
	return
}

// ID computes an ID for a given pass header.
func (header PassHeader) ID() (PassID, error) {
	headerJson, err := json.Marshal(header)
	if err != nil {
		return PassID{}, err
	}
	return sha3.Sum256([]byte(headerJson)), nil
}

// IDFast computes an ID for a given pass header when trailing.
func (header *PassHeader) IDFast(trailerNum int) (*big.Int, int64) {
	if header.hasher == nil {
		header.hasher = NewPassHeaderHasher()
	}
	return header.hasher.Update(trailerNum, header)
}

// Compare returns true if the header indicates it is a better trail than "theirHeader" up to both points.
// "thisWhen" is the timestamp of when we stored this pass header.
// "theirWhen" is the timestamp of when we stored "theirHeader".
func (header PassHeader) Compare(theirHeader *PassHeader, thisWhen, theirWhen int64) bool {
	thisWorkInt := header.TrailWork.GetBigInt()
	theirWorkInt := theirHeader.TrailWork.GetBigInt()

	// most work wins
	if thisWorkInt.Cmp(theirWorkInt) > 0 {
		return true
	}
	if thisWorkInt.Cmp(theirWorkInt) < 0 {
		return false
	}

	// tie goes to the pass we stored first
	if thisWhen < theirWhen {
		return true
	}
	if thisWhen > theirWhen {
		return false
	}

	// if we still need to break a tie go by the lesser id
	thisID, err := header.ID()
	if err != nil {
		panic(err)
	}
	theirID, err := theirHeader.ID()
	if err != nil {
		panic(err)
	}
	return thisID.GetBigInt().Cmp(theirID.GetBigInt()) < 0
}

// String implements the Stringer interface
func (id PassID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalJSON marshals PassID as a hex string.
func (id PassID) MarshalJSON() ([]byte, error) {
	s := "\"" + id.String() + "\""
	return []byte(s), nil
}

// UnmarshalJSON unmarshals PassID hex string to PassID.
func (id *PassID) UnmarshalJSON(b []byte) error {
	if len(b) != 64+2 {
		return fmt.Errorf("Invalid pass ID")
	}
	idBytes, err := hex.DecodeString(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	copy(id[:], idBytes)
	return nil
}

// SetBigInt converts from big.Int to PassID.
func (id *PassID) SetBigInt(i *big.Int) *PassID {
	intBytes := i.Bytes()
	if len(intBytes) > 32 {
		panic("Too much work")
	}
	for i := 0; i < len(id); i++ {
		id[i] = 0x00
	}
	copy(id[32-len(intBytes):], intBytes)
	return id
}

// GetBigInt converts from PassID to big.Int.
func (id PassID) GetBigInt() *big.Int {
	return new(big.Int).SetBytes(id[:])
}
