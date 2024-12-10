package passtrail

// PassStorage is an interface for storing passes and their considerations.
type PassStorage interface {
	// Store is called to store all of the pass's information.
	Store(id PassID, pass *Pass, now int64) error

	// Get returns the referenced pass.
	GetPass(id PassID) (*Pass, error)

	// GetPassBytes returns the referenced pass as a byte slice.
	GetPassBytes(id PassID) ([]byte, error)

	// GetPassHeader returns the referenced pass's header and the timestamp of when it was stored.
	GetPassHeader(id PassID) (*PassHeader, int64, error)

	// GetConsideration returns a consideration within a pass and the pass's header.
	GetConsideration(id PassID, index int) (*Consideration, *PassHeader, error)
}
