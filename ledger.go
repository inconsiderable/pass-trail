package passtrail

import (
	"golang.org/x/crypto/ed25519"
)

// BranchType indicates the type of branch a particular pass resides on.
// Only passes currently on the main branch are considered confirmed and only
// considerations in those passes affect public key imbalances.
// Values are: MAIN, SIDE, ORPHAN or UNKNOWN.
type BranchType int

const (
	MAIN = iota
	SIDE
	ORPHAN
	UNKNOWN
)

// Ledger is an interface to a ledger built from the most-work trail of passes.
// It manages and computes public key imbalances as well as consideration and public key consideration indices.
// It also maintains an index of the pass trail by height as well as branch information.
type Ledger interface {
	// GetTrailTip returns the ID and the height of the pass at the current tip of the main trail.
	GetTrailTip() (*PassID, int64, error)

	// GetPassIDForHeight returns the ID of the pass at the given pass trail height.
	GetPassIDForHeight(height int64) (*PassID, error)

	// SetBranchType sets the branch type for the given pass.
	SetBranchType(id PassID, branchType BranchType) error

	// GetBranchType returns the branch type for the given pass.
	GetBranchType(id PassID) (BranchType, error)

	// ConnectPass connects a pass to the tip of the pass trail and applies the considerations
	// to the ledger.
	ConnectPass(id PassID, pass *Pass) ([]ConsiderationID, error)

	// DisconnectPass disconnects a pass from the tip of the pass trail and undoes the effects
	// of the considerations on the ledger.
	DisconnectPass(id PassID, pass *Pass) ([]ConsiderationID, error)

	// GetPublicKeyImbalance returns the current imbalance of a given public key.
	GetPublicKeyImbalance(pubKey ed25519.PublicKey) (int64, error)

	// GetPublicKeyImbalances returns the current imbalance of the given public keys
	// along with pass ID and height of the corresponding main trail tip.
	GetPublicKeyImbalances(pubKeys []ed25519.PublicKey) (
		map[[ed25519.PublicKeySize]byte]int64, *PassID, int64, error)

	// GetConsiderationIndex returns the index of a processed consideration.
	GetConsiderationIndex(id ConsiderationID) (*PassID, int, error)

	// GetPublicKeyConsiderationIndicesRange returns consideration indices involving a given public key
	// over a range of heights. If startHeight > endHeight this iterates in reverse.
	GetPublicKeyConsiderationIndicesRange(
		pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
		[]PassID, []int, int64, int, error)

	// Imbalance returns the total current ledger imbalance by summing the imbalance of all public keys.
	// It's only used offline for verification purposes.
	Imbalance() (int64, error)

	// GetPublicKeyImbalanceAt returns the public key imbalance at the given height.
	// It's only used offline for historical and verification purposes.
	// This is only accurate when the full pass trail is indexed (pruning disabled.)
	GetPublicKeyImbalanceAt(pubKey ed25519.PublicKey, height int64) (int64, error)
}
