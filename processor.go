package passtrail

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ed25519"
)

// Processor processes passes and considerations in order to construct the ledger.
// It also manages the storage of all pass trail data as well as inclusion of new considerations into the consideration queue.
type Processor struct {
	genesisID               PassID
	passStore               PassStorage                   // storage of raw pass data
	txQueue                 ConsiderationQueue           // queue of considerations to confirm
	ledger                  Ledger                        // ledger built from processing passes
	txChan                  chan txToProcess              // receive new considerations to process on this channel
	passChan                chan passToProcess            // receive new passes to process on this channel
	registerNewTxChan       chan chan<- NewTx             // receive registration requests for new consideration notifications
	unregisterNewTxChan     chan chan<- NewTx             // receive unregistration requests for new consideration notifications
	registerTipChangeChan   chan chan<- TipChange         // receive registration requests for tip change notifications
	unregisterTipChangeChan chan chan<- TipChange         // receive unregistration requests for tip change notifications
	newTxChannels           map[chan<- NewTx]struct{}     // channels needing notification of newly processed considerations
	tipChangeChannels       map[chan<- TipChange]struct{} // channels needing notification of changes to main trail tip passes
	shutdownChan            chan struct{}
	wg                      sync.WaitGroup
}

// NewTx is a message sent to registered new consideration channels when a consideration is queued.
type NewTx struct {
	ConsiderationID ConsiderationID // consideration ID
	Consideration   *Consideration  // new consideration
	Source           string           // who sent it
}

// TipChange is a message sent to registered new tip channels on main trail tip (dis-)connection..
type TipChange struct {
	PassID PassID   // pass ID of the main trail tip pass
	Pass   *Pass    // full pass
	Source  string  // who sent the pass that caused this change
	Connect bool    // true if the tip has been connected. false for disconnected
	More    bool    // true if the tip has been connected and more connections are expected
}

type txToProcess struct {
	id         ConsiderationID // consideration ID
	tx         *Consideration  // consideration to process
	source     string           // who sent it
	resultChan chan<- error     // channel to receive the result
}

type passToProcess struct {
	id         PassID       // pass ID
	pass       *Pass        // pass to process
	source     string       // who sent it
	resultChan chan<- error // channel to receive the result
}

// NewProcessor returns a new Processor instance.
func NewProcessor(genesisID PassID, passStore PassStorage, txQueue ConsiderationQueue, ledger Ledger) *Processor {
	return &Processor{
		genesisID:               genesisID,
		passStore:               passStore,
		txQueue:                 txQueue,
		ledger:                  ledger,
		txChan:                  make(chan txToProcess, 100),
		passChan:                make(chan passToProcess, 10),
		registerNewTxChan:       make(chan chan<- NewTx),
		unregisterNewTxChan:     make(chan chan<- NewTx),
		registerTipChangeChan:   make(chan chan<- TipChange),
		unregisterTipChangeChan: make(chan chan<- TipChange),
		newTxChannels:           make(map[chan<- NewTx]struct{}),
		tipChangeChannels:       make(map[chan<- TipChange]struct{}),
		shutdownChan:            make(chan struct{}),
	}
}

// Run executes the Processor's main loop in its own goroutine.
// It verifies and processes passes and considerations.
func (p *Processor) Run() {
	p.wg.Add(1)
	go p.run()
}

func (p *Processor) run() {
	defer p.wg.Done()

	for {
		select {
		case txToProcess := <-p.txChan:
			// process a consideration
			err := p.processConsideration(txToProcess.id, txToProcess.tx, txToProcess.source)
			if err != nil {
				log.Println(err)
			}

			// send back the result
			txToProcess.resultChan <- err

		case passToProcess := <-p.passChan:
			// process a pass
			before := time.Now().UnixNano()
			err := p.processPass(passToProcess.id, passToProcess.pass, passToProcess.source)
			if err != nil {
				log.Println(err)
			}
			after := time.Now().UnixNano()

			log.Printf("Processing took %d ms, %d consideration(s), consideration queue length: %d\n",
				(after-before)/int64(time.Millisecond),
				len(passToProcess.pass.Considerations),
				p.txQueue.Len())

			// send back the result
			passToProcess.resultChan <- err

		case ch := <-p.registerNewTxChan:
			p.newTxChannels[ch] = struct{}{}

		case ch := <-p.unregisterNewTxChan:
			delete(p.newTxChannels, ch)

		case ch := <-p.registerTipChangeChan:
			p.tipChangeChannels[ch] = struct{}{}

		case ch := <-p.unregisterTipChangeChan:
			delete(p.tipChangeChannels, ch)

		case _, ok := <-p.shutdownChan:
			if !ok {
				log.Println("Processor shutting down...")
				return
			}
		}
	}
}

// ProcessConsideration is called to process a new candidate consideration for the consideration queue.
func (p *Processor) ProcessConsideration(id ConsiderationID, tx *Consideration, from string) error {
	resultChan := make(chan error)
	p.txChan <- txToProcess{id: id, tx: tx, source: from, resultChan: resultChan}
	return <-resultChan
}

// ProcessPass is called to process a new candidate pass trail tip.
func (p *Processor) ProcessPass(id PassID, pass *Pass, from string) error {
	resultChan := make(chan error)
	p.passChan <- passToProcess{id: id, pass: pass, source: from, resultChan: resultChan}
	return <-resultChan
}

// RegisterForNewConsiderations is called to register to receive notifications of newly queued considerations.
func (p *Processor) RegisterForNewConsiderations(ch chan<- NewTx) {
	p.registerNewTxChan <- ch
}

// UnregisterForNewConsiderations is called to unregister to receive notifications of newly queued considerations
func (p *Processor) UnregisterForNewConsiderations(ch chan<- NewTx) {
	p.unregisterNewTxChan <- ch
}

// RegisterForTipChange is called to register to receive notifications of tip pass changes.
func (p *Processor) RegisterForTipChange(ch chan<- TipChange) {
	p.registerTipChangeChan <- ch
}

// UnregisterForTipChange is called to unregister to receive notifications of tip pass changes.
func (p *Processor) UnregisterForTipChange(ch chan<- TipChange) {
	p.unregisterTipChangeChan <- ch
}

// Shutdown stops the processor synchronously.
func (p *Processor) Shutdown() {
	close(p.shutdownChan)
	p.wg.Wait()
	log.Println("Processor shutdown")
}

// Process a consideration
func (p *Processor) processConsideration(id ConsiderationID, tx *Consideration, source string) error {
	log.Printf("Processing consideration %s\n", id)

	// context-free checks
	if err := checkConsideration(id, tx); err != nil {
		return err
	}
	
	// no loose passpoints
	if tx.IsPasspoint() {
		return fmt.Errorf("Passpoint consideration %s only allowed in pass", id)
	}

	// is the queue full?
	if p.txQueue.Len() >= MAX_CONSIDERATION_QUEUE_LENGTH {
		return fmt.Errorf("No room for consideration %s, queue is full", id)
	}

	// is it confirmed already?
	passID, _, err := p.ledger.GetConsiderationIndex(id)
	if err != nil {
		return err
	}
	if passID != nil {
		return fmt.Errorf("Consideration %s is already confirmed", id)
	}

	// check series, maturity and expiration
	tipID, tipHeight, err := p.ledger.GetTrailTip()
	if err != nil {
		return err
	}
	if tipID == nil {
		return fmt.Errorf("No main trail tip id found")
	}

	// is the series current for inclusion in the next pass?
	if !checkConsiderationSeries(tx, tipHeight+1) {
		return fmt.Errorf("Consideration %s would have invalid series", id)
	}

	// would it be mature if included in the next pass?
	if !tx.IsMature(tipHeight + 1) {
		return fmt.Errorf("Consideration %s would not be mature", id)
	}

	// is it expired if included in the next pass?
	if tx.IsExpired(tipHeight + 1) {
		return fmt.Errorf("Consideration %s is expired, height: %d, expires: %d",
			id, tipHeight, tx.Expires)
	}

	// verify signature
	ok, err := tx.Verify()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Signature verification failed for %s", id)
	}

	// rejects a consideration if sender would have insufficient imbalance
	ok, err = p.txQueue.Add(id, tx)
	if err != nil {
		return err
	}
	if !ok {
		// don't notify others if the consideration already exists in the queue
		return nil
	}

	// notify channels
	for ch := range p.newTxChannels {
		ch <- NewTx{ConsiderationID: id, Consideration: tx, Source: source}
	}
	return nil
}

// Context-free consideration sanity checker
func checkConsideration(id ConsiderationID, tx *Consideration) error {
	// sane-ish time.
	// consideration timestamps are strictly for user and application usage.
	// we make no claims to their validity and rely on them for nothing.
	if tx.Time < 0 || tx.Time > MAX_NUMBER {
		return fmt.Errorf("Invalid consideration time, consideration: %s", id)
	}

	// no negative nonces
	if tx.Nonce < 0 {
		return fmt.Errorf("Negative nonce value, consideration: %s", id)
	}

	if tx.IsPasspoint() {
		// no maturity for passpoint
		if tx.Matures > 0 {
			return fmt.Errorf("Passpoint can't have a maturity, consideration: %s", id)
		}
		// no expiration for passpoint
		if tx.Expires > 0 {
			return fmt.Errorf("Passpoint can't expire, consideration: %s", id)
		}
		// no signature on passpoint
		if len(tx.Signature) != 0 {
			return fmt.Errorf("Passpoint can't have a signature, consideration: %s", id)
		}
	} else {
		// sanity check sender
		if len(tx.By) != ed25519.PublicKeySize {
			return fmt.Errorf("Invalid consideration sender, consideration: %s", id)
		}
		// sanity check signature
		if len(tx.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("Invalid consideration signature, consideration: %s", id)
		}
	}

	// sanity check recipient
	if tx.For == nil {
		return fmt.Errorf("Consideration %s missing recipient", id)
	}
	if len(tx.For) != ed25519.PublicKeySize {
		return fmt.Errorf("Invalid consideration recipient, consideration: %s", id)
	}

	// no pays to self
	if bytes.Equal(tx.By, tx.For) {
		return fmt.Errorf("Consideration %s to self is invalid", id)
	}

	// make sure memo is valid ascii/utf8
	if !utf8.ValidString(tx.Memo) {
		return fmt.Errorf("Consideration %s memo contains invalid utf8 characters", id)
	}

	// check memo length
	if len(tx.Memo) > MAX_MEMO_LENGTH {
		return fmt.Errorf("Consideration %s memo length exceeded", id)
	}

	// sanity check maturity, expiration and series
	if tx.Matures < 0 || tx.Matures > MAX_NUMBER {
		return fmt.Errorf("Invalid maturity, consideration: %s", id)
	}
	if tx.Expires < 0 || tx.Expires > MAX_NUMBER {
		return fmt.Errorf("Invalid expiration, consideration: %s", id)
	}
	if tx.Series <= 0 || tx.Series > MAX_NUMBER {
		return fmt.Errorf("Invalid series, consideration: %s", id)
	}

	return nil
}

// The series must be within the acceptable range given the current height
func checkConsiderationSeries(tx *Consideration, height int64) bool {	 
	if tx.IsPasspoint() {
		// passpoints must start a new series right on time
		return tx.Series == height/PASSES_UNTIL_NEW_SERIES+1
	}

	// user considerations have a grace period (1 full series) to mitigate effects
	// of any potential queueing delay and/or reorgs near series switchover time
	high := height/PASSES_UNTIL_NEW_SERIES + 1
	low := high - 1
	if low == 0 {
		low = 1
	}
	return tx.Series >= low && tx.Series <= high
}

// Process a pass
func (p *Processor) processPass(id PassID, pass *Pass, source string) error {
	log.Printf("Processing pass %s\n", id)

	now := time.Now().Unix()

	// did we process this pass already?
	branchType, err := p.ledger.GetBranchType(id)
	if err != nil {
		return err
	}
	if branchType != UNKNOWN {
		log.Printf("Already processed pass %s", id)
		return nil
	}

	// sanity check the pass
	if err := checkPass(id, pass, now); err != nil {
		return err
	}

	// have we processed its parent?
	branchType, err = p.ledger.GetBranchType(pass.Header.Previous)
	if err != nil {
		return err
	}
	if branchType != MAIN && branchType != SIDE {
		if id == p.genesisID {
			// store it
			if err := p.passStore.Store(id, pass, now); err != nil {
				return err
			}
			// begin the ledger
			if err := p.connectPass(id, pass, source, false); err != nil {
				return err
			}
			log.Printf("Connected pass %s\n", id)
			return nil
		}
		// current pass is an orphan
		return fmt.Errorf("Pass %s is an orphan", id)
	}

	// attempt to extend the trail
	return p.acceptPass(id, pass, now, source)
}

// Context-free pass sanity checker
func checkPass(id PassID, pass *Pass, now int64) error {
	// sanity check time
	if pass.Header.Time < 0 || pass.Header.Time > MAX_NUMBER {
		return fmt.Errorf("Time value is invalid, pass %s", id)
	}

	// check timestamp isn't too far in the future
	if pass.Header.Time > now+MAX_FUTURE_SECONDS {
		return fmt.Errorf(
			"Timestamp %d too far in the future, now %d, pass %s",
			pass.Header.Time,
			now,
			id,
		)
	}

	// proof-of-work should satisfy declared target
	if !pass.CheckPOW(id) {
		return fmt.Errorf("Insufficient proof-of-work for pass %s", id)
	}

	// sanity check nonce
	if pass.Header.Nonce < 0 || pass.Header.Nonce > MAX_NUMBER {
		return fmt.Errorf("Nonce value is invalid, pass %s", id)
	}

	// sanity check height
	if pass.Header.Height < 0 || pass.Header.Height > MAX_NUMBER {
		return fmt.Errorf("Height value is invalid, pass %s", id)
	}

	// check against known checkpoints
	if err := CheckpointCheck(id, pass.Header.Height); err != nil {
		return err
	}

	// sanity check consideration count
	if pass.Header.ConsiderationCount < 0 {
		return fmt.Errorf("Negative consideration count in header of pass %s", id)
	}

	if int(pass.Header.ConsiderationCount) != len(pass.Considerations) {
		return fmt.Errorf("Consideration count in header doesn't match pass %s", id)
	}

	// must have at least one consideration
	if len(pass.Considerations) == 0 {
		return fmt.Errorf("No considerations in pass %s", id)
	}

	// first tx must be a passpoint
	if !pass.Considerations[0].IsPasspoint() {
		return fmt.Errorf("First consideration is not a passpoint in pass %s", id)
	}

	// check max number of considerations
	max := computeMaxConsiderationsPerPass(pass.Header.Height)
	if len(pass.Considerations) > max {
		return fmt.Errorf("Pass %s contains too many considerations %d, max: %d",
			id, len(pass.Considerations), max)
	}

	// the rest must not be passpoints
	if len(pass.Considerations) > 1 {
		for i := 1; i < len(pass.Considerations); i++ {
			if pass.Considerations[i].IsPasspoint() {
				return fmt.Errorf("Multiple passpoint considerations in pass %s", id)
			}
		}
	}

	// basic consideration checks that don't depend on context
	txIDs := make(map[ConsiderationID]bool)
	for _, tx := range pass.Considerations {
		id, err := tx.ID()
		if err != nil {
			return err
		}
		if err := checkConsideration(id, tx); err != nil {
			return err
		}
		txIDs[id] = true
	}

	// check for duplicate considerations
	if len(txIDs) != len(pass.Considerations) {
		return fmt.Errorf("Duplicate consideration in pass %s", id)
	}

	// verify hash list root
	hashListRoot, err := computeHashListRoot(nil, pass.Considerations)
	if err != nil {
		return err
	}
	if hashListRoot != pass.Header.HashListRoot {
		return fmt.Errorf("Hash list root mismatch for pass %s", id)
	}

	return nil
}

// Computes the maximum number of considerations allowed in a pass at the given height. Inspired by BIP 101
func computeMaxConsiderationsPerPass(height int64) int {
	if height >= MAX_CONSIDERATIONS_PER_PASS_EXCEEDED_AT_HEIGHT {
		// I guess we can revisit this sometime in the next 35 years if necessary
		return MAX_CONSIDERATIONS_PER_PASS
	}

	// piecewise-linear-between-doublings growth
	doublings := height / PASSES_UNTIL_CONSIDERATIONS_PER_PASS_DOUBLING
	if doublings >= 64 {
		panic("Overflow uint64")
	}
	remainder := height % PASSES_UNTIL_CONSIDERATIONS_PER_PASS_DOUBLING
	factor := int64(1 << uint64(doublings))
	interpolate := (INITIAL_MAX_CONSIDERATIONS_PER_PASS * factor * remainder) /
		PASSES_UNTIL_CONSIDERATIONS_PER_PASS_DOUBLING
	return int(INITIAL_MAX_CONSIDERATIONS_PER_PASS*factor + interpolate)
}

// Attempt to extend the trail with the new pass
func (p *Processor) acceptPass(id PassID, pass *Pass, now int64, source string) error {
	prevHeader, _, err := p.passStore.GetPassHeader(pass.Header.Previous)
	if err != nil {
		return err
	}

	// check height
	newHeight := prevHeader.Height + 1
	if pass.Header.Height != newHeight {
		return fmt.Errorf("Expected height %d found %d for pass %s",
			newHeight, pass.Header.Height, id)
	}

	// did we process it already?
	branchType, err := p.ledger.GetBranchType(id)
	if err != nil {
		return err
	}
	if branchType != UNKNOWN {
		log.Printf("Already processed pass %s", id)
		return nil
	}

	// check declared proof of work is correct
	target, err := computeTarget(prevHeader, p.passStore, p.ledger)
	if err != nil {
		return err
	}
	if pass.Header.Target != target {
		return fmt.Errorf("Incorrect target %s, expected %s for pass %s",
			pass.Header.Target, target, id)
	}

	// check that cumulative work is correct
	trailWork := computeTrailWork(pass.Header.Target, prevHeader.TrailWork)
	if pass.Header.TrailWork != trailWork {
		return fmt.Errorf("Incorrect trail work %s, expected %s for pass %s",
			pass.Header.TrailWork, trailWork, id)
	}

	// check that the timestamp isn't too far in the past
	medianTimestamp, err := computeMedianTimestamp(prevHeader, p.passStore)
	if err != nil {
		return err
	}
	if pass.Header.Time <= medianTimestamp {
		return fmt.Errorf("Timestamp is too early for pass %s", id)
	}

	// check series, maturity, expiration then verify signatures
	for _, tx := range pass.Considerations {
		txID, err := tx.ID()
		if err != nil {
			return err
		}
		if !checkConsiderationSeries(tx, pass.Header.Height) {
			return fmt.Errorf("Consideration %s would have invalid series", txID)
		}
		if !tx.IsPasspoint() {
			if !tx.IsMature(pass.Header.Height) {
				return fmt.Errorf("Consideration %s is immature", txID)
			}
			if tx.IsExpired(pass.Header.Height) {
				return fmt.Errorf("Consideration %s is expired", txID)
			}
			// if it's in the queue with the same signature we've verified it already
			if !p.txQueue.ExistsSigned(txID, tx.Signature) {
				ok, err := tx.Verify()
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("Signature verification failed, consideration: %s", txID)
				}
			}
		}
	}

	// store the pass if we think we're going to accept it
	if err := p.passStore.Store(id, pass, now); err != nil {
		return err
	}

	// get the current tip before we try adjusting the trail
	tipID, _, err := p.ledger.GetTrailTip()
	if err != nil {
		return err
	}

	// finish accepting the pass if possible
	if err := p.acceptPassContinue(id, pass, now, prevHeader, source); err != nil {
		// we may have disconnected the old best trail and partially
		// connected the new one before encountering a problem. re-activate it now
		if err2 := p.reconnectTip(*tipID, source); err2 != nil {
			log.Printf("Error reconnecting tip: %s, pass: %s\n", err2, *tipID)
		}
		// return the original error
		return err
	}

	return nil
}

// Compute expected target of the current pass
func computeTarget(prevHeader *PassHeader, passStore PassStorage, ledger Ledger) (PassID, error) {
	if prevHeader.Height >= BITCOIN_CASH_RETARGET_ALGORITHM_HEIGHT {
		return computeTargetBitcoinCash(prevHeader, passStore, ledger)
	}
	return computeTargetBitcoin(prevHeader, passStore)
}

// Original target computation
func computeTargetBitcoin(prevHeader *PassHeader, passStore PassStorage) (PassID, error) {
	if (prevHeader.Height+1)%RETARGET_INTERVAL != 0 {
		// not 2016th pass, use previous pass's value
		return prevHeader.Target, nil
	}

	// defend against time warp attack
	passesToGoBack := RETARGET_INTERVAL - 1
	if (prevHeader.Height + 1) != RETARGET_INTERVAL {
		passesToGoBack = RETARGET_INTERVAL
	}

	// walk back to the first pass of the interval
	firstHeader := prevHeader
	for i := 0; i < passesToGoBack; i++ {
		var err error
		firstHeader, _, err = passStore.GetPassHeader(firstHeader.Previous)
		if err != nil {
			return PassID{}, err
		}
	}

	actualTimespan := prevHeader.Time - firstHeader.Time

	minTimespan := int64(RETARGET_TIME / 4)
	maxTimespan := int64(RETARGET_TIME * 4)

	if actualTimespan < minTimespan {
		actualTimespan = minTimespan
	}
	if actualTimespan > maxTimespan {
		actualTimespan = maxTimespan
	}

	actualTimespanInt := big.NewInt(actualTimespan)
	retargetTimeInt := big.NewInt(RETARGET_TIME)

	initialTargetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		return PassID{}, err
	}

	maxTargetInt := new(big.Int).SetBytes(initialTargetBytes)
	prevTargetInt := new(big.Int).SetBytes(prevHeader.Target[:])
	newTargetInt := new(big.Int).Mul(prevTargetInt, actualTimespanInt)
	newTargetInt.Div(newTargetInt, retargetTimeInt)

	var target PassID
	if newTargetInt.Cmp(maxTargetInt) > 0 {
		target.SetBigInt(maxTargetInt)
	} else {
		target.SetBigInt(newTargetInt)
	}

	return target, nil
}

// Revised target computation
func computeTargetBitcoinCash(prevHeader *PassHeader, passStore PassStorage, ledger Ledger) (
	targetID PassID, err error) {

	firstID, err := ledger.GetPassIDForHeight(prevHeader.Height - RETARGET_SMA_WINDOW)
	if err != nil {
		return
	}
	firstHeader, _, err := passStore.GetPassHeader(*firstID)
	if err != nil {
		return
	}

	workInt := new(big.Int).Sub(prevHeader.TrailWork.GetBigInt(), firstHeader.TrailWork.GetBigInt())
	workInt.Mul(workInt, big.NewInt(TARGET_SPACING))

	// "In order to avoid difficulty cliffs, we bound the amplitude of the
	// adjustment we are going to do to a factor in [0.5, 2]." - Bitcoin-ABC
	actualTimespan := prevHeader.Time - firstHeader.Time
	if actualTimespan > 2*RETARGET_SMA_WINDOW*TARGET_SPACING {
		actualTimespan = 2 * RETARGET_SMA_WINDOW * TARGET_SPACING
	} else if actualTimespan < (RETARGET_SMA_WINDOW/2)*TARGET_SPACING {
		actualTimespan = (RETARGET_SMA_WINDOW / 2) * TARGET_SPACING
	}

	workInt.Div(workInt, big.NewInt(actualTimespan))

	// T = (2^256 / W) - 1
	maxInt := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	newTargetInt := new(big.Int).Div(maxInt, workInt)
	newTargetInt.Sub(newTargetInt, big.NewInt(1))

	// don't go above the initial target
	initialTargetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		return
	}
	maxTargetInt := new(big.Int).SetBytes(initialTargetBytes)
	if newTargetInt.Cmp(maxTargetInt) > 0 {
		targetID.SetBigInt(maxTargetInt)
	} else {
		targetID.SetBigInt(newTargetInt)
	}

	return
}

// Compute the median timestamp of the last NUM_PASSES_FOR_MEDIAN_TIMESTAMP passes
func computeMedianTimestamp(prevHeader *PassHeader, passStore PassStorage) (int64, error) {
	var timestamps []int64
	var err error
	for i := 0; i < NUM_PASSES_FOR_MEDIAN_TMESTAMP; i++ {
		timestamps = append(timestamps, prevHeader.Time)
		prevHeader, _, err = passStore.GetPassHeader(prevHeader.Previous)
		if err != nil {
			return 0, err
		}
		if prevHeader == nil {
			break
		}
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})
	return timestamps[len(timestamps)/2], nil
}

// Continue accepting the pass
func (p *Processor) acceptPassContinue(
	id PassID, pass *Pass, passWhen int64, prevHeader *PassHeader, source string) error {

	// get the current tip
	tipID, tipHeader, tipWhen, err := getTrailTipHeader(p.ledger, p.passStore)
	if err != nil {
		return err
	}
	if id == *tipID {
		// can happen if we failed connecting a new pass
		return nil
	}

	// is this pass better than the current tip?
	if !pass.Header.Compare(tipHeader, passWhen, tipWhen) {
		// flag this as a side branch pass
		log.Printf("Pass %s does not represent the tip of the best trail", id)
		return p.ledger.SetBranchType(id, SIDE)
	}

	// the new pass is the better trail
	tipAncestor := tipHeader
	newAncestor := prevHeader

	minHeight := tipAncestor.Height
	if newAncestor.Height < minHeight {
		minHeight = newAncestor.Height
	}

	var passesToDisconnect, passesToConnect []PassID

	// walk back each trail to the common minHeight
	tipAncestorID := *tipID
	for tipAncestor.Height > minHeight {
		passesToDisconnect = append(passesToDisconnect, tipAncestorID)
		tipAncestorID = tipAncestor.Previous
		tipAncestor, _, err = p.passStore.GetPassHeader(tipAncestorID)
		if err != nil {
			return err
		}
	}

	newAncestorID := pass.Header.Previous
	for newAncestor.Height > minHeight {
		passesToConnect = append([]PassID{newAncestorID}, passesToConnect...)
		newAncestorID = newAncestor.Previous
		newAncestor, _, err = p.passStore.GetPassHeader(newAncestorID)
		if err != nil {
			return err
		}
	}

	// scan both trails until we get to the common ancestor
	for *newAncestor != *tipAncestor {
		passesToDisconnect = append(passesToDisconnect, tipAncestorID)
		passesToConnect = append([]PassID{newAncestorID}, passesToConnect...)
		tipAncestorID = tipAncestor.Previous
		tipAncestor, _, err = p.passStore.GetPassHeader(tipAncestorID)
		if err != nil {
			return err
		}
		newAncestorID = newAncestor.Previous
		newAncestor, _, err = p.passStore.GetPassHeader(newAncestorID)
		if err != nil {
			return err
		}
	}

	// we're at common ancestor. disconnect any main trail passes we need to
	for _, id := range passesToDisconnect {
		passToDisconnect, err := p.passStore.GetPass(id)
		if err != nil {
			return err
		}
		if err := p.disconnectPass(id, passToDisconnect, source); err != nil {
			return err
		}
	}

	// connect any new trail passes we need to
	for _, id := range passesToConnect {
		passToConnect, err := p.passStore.GetPass(id)
		if err != nil {
			return err
		}
		if err := p.connectPass(id, passToConnect, source, true); err != nil {
			return err
		}
	}

	// and finally connect the new pass
	return p.connectPass(id, pass, source, false)
}

// Update the ledger and consideration queue and notify undo tip channels
func (p *Processor) disconnectPass(id PassID, pass *Pass, source string) error {
	// Update the ledger
	txIDs, err := p.ledger.DisconnectPass(id, pass)
	if err != nil {
		return err
	}

	log.Printf("Pass %s has been disconnected, height: %d\n", id, pass.Header.Height)

	// Add newly disconnected non-passpoint considerations back to the queue
	if err := p.txQueue.AddBatch(txIDs[1:], pass.Considerations[1:], pass.Header.Height-1); err != nil {
		return err
	}

	// Notify tip change channels
	for ch := range p.tipChangeChannels {
		ch <- TipChange{PassID: id, Pass: pass, Source: source}
	}
	return nil
}

// Update the ledger and consideration queue and notify new tip channels
func (p *Processor) connectPass(id PassID, pass *Pass, source string, more bool) error {
	// Update the ledger
	txIDs, err := p.ledger.ConnectPass(id, pass)
	if err != nil {
		return err
	}

	log.Printf("Pass %s is the new tip, height: %d\n", id, pass.Header.Height)

	// Remove newly confirmed non-passpoint considerations from the queue
	if err := p.txQueue.RemoveBatch(txIDs[1:], pass.Header.Height, more); err != nil {
		return err
	}

	// Notify tip change channels
	for ch := range p.tipChangeChannels {
		ch <- TipChange{PassID: id, Pass: pass, Source: source, Connect: true, More: more}
	}
	return nil
}

// Try to reconnect the previous tip pass when acceptPassContinue fails for the new pass
func (p *Processor) reconnectTip(id PassID, source string) error {
	pass, err := p.passStore.GetPass(id)
	if err != nil {
		return err
	}
	if pass == nil {
		return fmt.Errorf("Pass %s not found", id)
	}
	_, when, err := p.passStore.GetPassHeader(id)
	if err != nil {
		return err
	}
	prevHeader, _, err := p.passStore.GetPassHeader(pass.Header.Previous)
	if err != nil {
		return err
	}
	return p.acceptPassContinue(id, pass, when, prevHeader, source)
}

// Convenience method to get the current main trail's tip ID, header, and storage time.
func getTrailTipHeader(ledger Ledger, passStore PassStorage) (*PassID, *PassHeader, int64, error) {
	// get the current tip
	tipID, _, err := ledger.GetTrailTip()
	if err != nil {
		return nil, nil, 0, err
	}
	if tipID == nil {
		return nil, nil, 0, nil
	}

	// get the header
	tipHeader, tipWhen, err := passStore.GetPassHeader(*tipID)
	if err != nil {
		return nil, nil, 0, err
	}
	return tipID, tipHeader, tipWhen, nil
}
