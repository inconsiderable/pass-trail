package passtrail

import "golang.org/x/crypto/ed25519"

// Protocol is the name of this version of the passtrail peer protocol.
const Protocol = "passtrail.1"

// Message is a message frame for all messages in the passtrail.1 protocol.
type Message struct {
	Type string      `json:"type"`
	Body interface{} `json:"body,omitempty"`
}

// InvPassMessage is used to communicate passes available for download.
// Type: "inv_pass".
type InvPassMessage struct {
	PassIDs []PassID `json:"pass_ids"`
}

// GetPassMessage is used to request a pass for download.
// Type: "get_pass".
type GetPassMessage struct {
	PassID PassID `json:"pass_id"`
}

// GetPassByHeightMessage is used to request a pass for download.
// Type: "get_pass_by_height".
type GetPassByHeightMessage struct {
	Height int64 `json:"height"`
}

// PassMessage is used to send a peer a complete pass.
// Type: "pass".
type PassMessage struct {
	PassID *PassID `json:"pass_id,omitempty"`
	Pass   *Pass   `json:"pass,omitempty"`
}

// GetPassHeaderMessage is used to request a pass header.
// Type: "get_pass_header".
type GetPassHeaderMessage struct {
	PassID PassID `json:"pass_id"`
}

// GetPassHeaderByHeightMessage is used to request a pass header.
// Type: "get_pass_header_by_height".
type GetPassHeaderByHeightMessage struct {
	Height int64 `json:"height"`
}

// PassHeaderMessage is used to send a peer a pass's header.
// Type: "pass_header".
type PassHeaderMessage struct {
	PassID     *PassID     `json:"pass_id,omitempty"`
	PassHeader *PassHeader `json:"header,omitempty"`
}

// FindCommonAncestorMessage is used to find a common ancestor with a peer.
// Type: "find_common_ancestor".
type FindCommonAncestorMessage struct {
	PassIDs []PassID `json:"pass_ids"`
}

// GetProfile requests a public key's profile
// Type: "get_profile".
type GetProfileMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// ProfileMessage is used to send a public key's profile to a peer.
// Type: "profile".
type ProfileMessage struct {
	PublicKey     ed25519.PublicKey         `json:"public_key"`
	Ranking   	  float64       			`json:"ranking"`
	Imbalance 	  int64                     `json:"imbalance"`
	Focale 	  	  string                    `json:"focale"`
	PassID        PassID                    `json:"pass_id,omitempty"`
	Height        int64                     `json:"height,omitempty"`
	Error         string                    `json:"error,omitempty"`
}

// GetGraph requests a public key's pass graph
// Type: "get_graph".
type GetGraphMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// PassGraphMessage is used to send a public key's pass graph considerations to a peer.
// Type: "graph".
type GraphMessage struct {
	PassID   PassID             `json:"pass_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Graph   string       		`json:"graph"`
}

// GetRankingMessage requests a public key's considerability ranking.
// Type: "get_ranking".
type GetRankingMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// RankingMessage is used to send a public key's considerability ranking to a peer.
// Type: "ranking".
type RankingMessage struct {
	PassID   PassID             `json:"pass_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Ranking   	  float64       `json:"ranking"`
	Error     string            `json:"error,omitempty"`
}

// GetRankingsMessage requests a set of public key rankings.
// Type: "get_rankings".
type GetRankingsMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
}

// RankingsMessage is used to send public key rankings to a peer.
// Type: "rankings".
type RankingsMessage struct {
	PassID   PassID             `json:"pass_id,omitempty"`
	Height   int64              `json:"height,omitempty"`
	Rankings []PublicKeyRanking `json:"rankings,omitempty"`
	Error    string             `json:"error,omitempty"`
}

// PublicKeyRanking is an entry in the RankingsMessage's Rankings field.
type PublicKeyRanking struct {
	PublicKey string 			`json:"public_key"`
	Ranking   float64           `json:"ranking"`
}

// GetImbalanceMessage requests a public key's imbalance.
// Type: "get_imbalance".
type GetImbalanceMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// ImbalanceMessage is used to send a public key's imbalance to a peer.
// Type: "imbalance".
type ImbalanceMessage struct {
	PassID    *PassID           `json:"pass_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Imbalance int64             `json:"imbalance"`
	Error     string            `json:"error,omitempty"`
}

// GetImbalancesMessage requests a set of public key imbalances.
// Type: "get_imbalances".
type GetImbalancesMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
}

// ImbalancesMessage is used to send public key imbalances to a peer.
// Type: "imbalances".
type ImbalancesMessage struct {
	PassID  *PassID                 `json:"pass_id,omitempty"`
	Height   int64                  `json:"height,omitempty"`
	Imbalances []PublicKeyImbalance `json:"imbalances,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

// PublicKeyImbalance is an entry in the ImbalancesMessage's Imbalances field.
type PublicKeyImbalance struct {
	PublicKey ed25519.PublicKey   `json:"public_key"`
	Imbalance   int64             `json:"imbalance"`
}

// GetConsiderationMessage is used to request a confirmed consideration.
// Type: "get_consideration".
type GetConsiderationMessage struct {
	ConsiderationID ConsiderationID `json:"consideration_id"`
}

// ConsiderationMessage is used to send a peer a confirmed consideration.
// Type: "consideration"
type ConsiderationMessage struct {
	PassID       *PassID              `json:"pass_id,omitempty"`
	Height        int64               `json:"height,omitempty"`
	ConsiderationID ConsiderationID `json:"consideration_id"`
	Consideration   *Consideration  `json:"consideration,omitempty"`
}

// TipHeaderMessage is used to send a peer the header for the tip pass in the pass trail.
// Type: "tip_header". It is sent in response to the empty "get_tip_header" message type.
type TipHeaderMessage struct {
	PassID     *PassID       `json:"pass_id,omitempty"`
	PassHeader *PassHeader   `json:"header,omitempty"`
	TimeSeen    int64        `json:"time_seen,omitempty"`
}

// PushConsiderationMessage is used to push a newly processed unconfirmed consideration to peers.
// Type: "push_consideration".
type PushConsiderationMessage struct {
	Consideration *Consideration `json:"consideration"`
}

// PushConsiderationResultMessage is sent in response to a PushConsiderationMessage.
// Type: "push_consideration_result".
type PushConsiderationResultMessage struct {
	ConsiderationID ConsiderationID `json:"consideration_id"`
	Error         string              `json:"error,omitempty"`
}

// FilterLoadMessage is used to request that we load a filter which is used to
// filter considerations returned to the peer based on interest.
// Type: "filter_load"
type FilterLoadMessage struct {
	Type   string `json:"type"`
	Filter []byte `json:"filter"`
}

// FilterAddMessage is used to request the addition of the given public keys to the current filter.
// The filter is created if it's not set.
// Type: "filter_add".
type FilterAddMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
}

// FilterResultMessage indicates whether or not the filter request was successful.
// Type: "filter_result".
type FilterResultMessage struct {
	Error string `json:"error,omitempty"`
}

// FilterPassMessage represents a pared down pass containing only considerations relevant to the peer given their filter.
// Type: "filter_pass".
type FilterPassMessage struct {
	PassID      PassID                `json:"pass_id"`
	Header       *PassHeader          `json:"header"`
	Considerations []*Consideration `json:"considerations"`
}

// FilterConsiderationQueueMessage returns a pared down view of the unconfirmed consideration queue containing only
// considerations relevant to the peer given their filter.
// Type: "filter_consideration_queue".
type FilterConsiderationQueueMessage struct {
	Considerations []*Consideration `json:"considerations"`
	Error        string               `json:"error,omitempty"`
}

// GetPublicKeyConsiderationsMessage requests considerations associated with a given public key over a given
// height range of the pass trail.
// Type: "get_public_key_considerations".
type GetPublicKeyConsiderationsMessage struct {
	PublicKey   ed25519.PublicKey `json:"public_key"`
	StartHeight int64             `json:"start_height"`
	StartIndex  int               `json:"start_index"`
	EndHeight   int64             `json:"end_height"`
	Limit       int               `json:"limit"`
}

// PublicKeyConsiderationsMessage is used to return a list of pass headers and the considerations relevant to
// the public key over a given height range of the pass trail.
// Type: "public_key_considerations".
type PublicKeyConsiderationsMessage struct {
	PublicKey    ed25519.PublicKey     `json:"public_key"`
	StartHeight  int64                 `json:"start_height"`
	StopHeight   int64                 `json:"stop_height"`
	StopIndex    int                   `json:"stop_index"`
	FilterPasses []*FilterPassMessage   `json:"filter_passes"`
	Error        string                `json:"error,omitempty"`
}

// PeerAddressesMessage is used to communicate a list of potential peer addresses known by a peer.
// Type: "peer_addresses". Sent in response to the empty "get_peer_addresses" message type.
type PeerAddressesMessage struct {
	Addresses []string `json:"addresses"`
}

// GetWorkMessage is used by a tracking peer to request tracking work.
// Type: "get_work"
type GetWorkMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
	Memo       string              `json:"memo,omitempty"`
}

// WorkMessage is used by a client to send work to perform to a tracking peer.
// The timestamp and nonce in the header can be manipulated by the tracking peer.
// It is the tracking peer's responsibility to ensure the timestamp is not set below
// the minimum timestamp and that the nonce does not exceed MAX_NUMBER (2^53-1).
// Type: "work"
type WorkMessage struct {
	WorkID  int32        `json:"work_id"`
	Header  *PassHeader  `json:"header"`
	MinTime int64        `json:"min_time"`
	Error   string       `json:"error,omitempty"`
}

// SubmitWorkMessage is used by a tracking peer to submit a potential solution to the client.
// Type: "submit_work"
type SubmitWorkMessage struct {
	WorkID int32        `json:"work_id"`
	Header *PassHeader  `json:"header"`
}

// SubmitWorkResultMessage is used to inform a tracking peer of the result of its work.
// Type: "submit_work_result"
type SubmitWorkResultMessage struct {
	WorkID int32  `json:"work_id"`
	Error  string `json:"error,omitempty"`
}
