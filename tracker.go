package passtrail

import (
	"log"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
)

// Tracker tries to track a new tip pass.
type Tracker struct {
	pubKeys        []ed25519.PublicKey // champions of any pass(-point) we track
	memo           string              // memo for pass(-point) of any passes we track
	passStore      PassStorage
	txQueue        ConsiderationQueue
	ledger         Ledger
	processor      *Processor
	num            int
	keyIndex       int
	hashUpdateChan chan int64
	shutdownChan   chan struct{}
	wg             sync.WaitGroup
}

// HashrateMonitor collects hash counts from all trackers in order to monitor and display the aggregate hashrate.
type HashrateMonitor struct {
	hashUpdateChan chan int64
	shutdownChan   chan struct{}
	wg             sync.WaitGroup
}

// NewTracker returns a new Tracker instance.
func NewTracker(pubKeys []ed25519.PublicKey, memo string,
	passStore PassStorage, txQueue ConsiderationQueue,
	ledger Ledger, processor *Processor,
	hashUpdateChan chan int64, num int) *Tracker {
	return &Tracker{
		pubKeys:        pubKeys,
		memo:           memo,
		passStore:      passStore,
		txQueue:        txQueue,
		ledger:         ledger,
		processor:      processor,
		num:            num,
		keyIndex:       rand.Intn(len(pubKeys)),
		hashUpdateChan: hashUpdateChan,
		shutdownChan:   make(chan struct{}),
	}
}

// NewHashrateMonitor returns a new HashrateMonitor instance.
func NewHashrateMonitor(hashUpdateChan chan int64) *HashrateMonitor {
	return &HashrateMonitor{
		hashUpdateChan: hashUpdateChan,
		shutdownChan:   make(chan struct{}),
	}
}

// Run executes the tracker's main loop in its own goroutine.
func (m *Tracker) Run() {
	m.wg.Add(1)
	go m.run()
}

func (m *Tracker) run() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// don't start tracking until we think we're synced.
	// we're just wasting time and slowing down the sync otherwise
	ibd, _, err := IsInitialPassDownload(m.ledger, m.passStore)
	if err != nil {
		panic(err)
	}
	if ibd {
		log.Printf("Tracker %d waiting for passtrail sync\n", m.num)
	ready:
		for {
			select {
			case _, ok := <-m.shutdownChan:
				if !ok {
					log.Printf("Tracker %d shutting down...\n", m.num)
					return
				}
			case <-ticker.C:
				var err error
				ibd, _, err = IsInitialPassDownload(m.ledger, m.passStore)
				if err != nil {
					panic(err)
				}
				if ibd == false {
					// time to start tracking
					break ready
				}
			}
		}
	}

	// register for tip changes
	tipChangeChan := make(chan TipChange, 1)
	m.processor.RegisterForTipChange(tipChangeChan)
	defer m.processor.UnregisterForTipChange(tipChangeChan)

	// register for new considerations
	newTxChan := make(chan NewTx, 1)
	m.processor.RegisterForNewConsiderations(newTxChan)
	defer m.processor.UnregisterForNewConsiderations(newTxChan)

	// main tracking loop
	var hashes, medianTimestamp int64
	var pass *Pass
	var targetInt *big.Int
	for {
		select {
		case tip := <-tipChangeChan:
			if !tip.Connect || tip.More {
				// only build off newly connected tip passes
				continue
			}

			// give up whatever pass we were working on
			log.Printf("Tracker %d received notice of new tip pass %s\n", m.num, tip.PassID)

			var err error
			// start working on a new pass
			pass, err = m.createNextPass(tip.PassID, tip.Pass.Header)
			if err != nil {
				// ledger state is broken
				panic(err)
			}
			// make sure we're at least +1 the median timestamp
			medianTimestamp, err = computeMedianTimestamp(tip.Pass.Header, m.passStore)
			if err != nil {
				panic(err)
			}
			if pass.Header.Time <= medianTimestamp {
				pass.Header.Time = medianTimestamp + 1
			}
			// convert our target to a big.Int
			targetInt = pass.Header.Target.GetBigInt()

		case newTx := <-newTxChan:
			log.Printf("Tracker %d received notice of new consideration %s\n", m.num, newTx.ConsiderationID)
			if pass == nil {
				// we're not working on a pass yet
				continue
			}

			if MAX_CONSIDERATIONS_TO_INCLUDE_PER_PASS != 0 &&
				len(pass.Considerations) >= MAX_CONSIDERATIONS_TO_INCLUDE_PER_PASS {
				log.Printf("Per-pass consideration limit hit (%d)\n", len(pass.Considerations))
				continue
			}

			// add the consideration to the pass
			if err := pass.AddConsideration(newTx.ConsiderationID, newTx.Consideration); err != nil {
				log.Printf("Error adding new consideration %s to pass: %s\n",
					newTx.ConsiderationID, err)
				// abandon the pass
				pass = nil
			}

		case _, ok := <-m.shutdownChan:
			if !ok {
				log.Printf("Tracker %d shutting down...\n", m.num)
				return
			}

		case <-ticker.C:
			// update hashcount for hashrate monitor
			m.hashUpdateChan <- hashes
			hashes = 0

			if pass != nil {
				// update pass time every so often
				now := time.Now().Unix()
				if now > medianTimestamp {
					pass.Header.Time = now
				}
			}

		default:
			if pass == nil {
				// find the tip to start working off of
				tipID, tipHeader, _, err := getTrailTipHeader(m.ledger, m.passStore)
				if err != nil {
					panic(err)
				}
				// create a new pass
				pass, err = m.createNextPass(*tipID, tipHeader)
				if err != nil {
					panic(err)
				}
				// make sure we're at least +1 the median timestamp
				medianTimestamp, err = computeMedianTimestamp(tipHeader, m.passStore)
				if err != nil {
					panic(err)
				}
				if pass.Header.Time <= medianTimestamp {
					pass.Header.Time = medianTimestamp + 1
				}
				// convert our target to a big.Int
				targetInt = pass.Header.Target.GetBigInt()
			}

			// hash the pass and check the proof-of-work
			idInt, attempts := pass.Header.IDFast(m.num)
			hashes += attempts
			if idInt.Cmp(targetInt) <= 0 {
				// found a solution
				id := new(PassID).SetBigInt(idInt)
				log.Printf("Tracker %d tracked new pass %s\n", m.num, *id)

				// process the pass
				if err := m.processor.ProcessPass(*id, pass, "localhost"); err != nil {
					log.Printf("Error processing tracked pass: %s\n", err)
				}

				pass = nil
				m.keyIndex = rand.Intn(len(m.pubKeys))
			} else {
				// no solution yet
				pass.Header.Nonce += attempts
				if pass.Header.Nonce > MAX_NUMBER {
					pass.Header.Nonce = 0
				}
			}
		}
	}
}

// Shutdown stops the tracker synchronously.
func (m *Tracker) Shutdown() {
	close(m.shutdownChan)
	m.wg.Wait()
	log.Printf("Tracker %d shutdown\n", m.num)
}

// Create a new pass off of the given tip pass.
func (m *Tracker) createNextPass(tipID PassID, tipHeader *PassHeader) (*Pass, error) {
	log.Printf("Tracker %d tracking new pass from current tip %s\n", m.num, tipID)
	pubKey := m.pubKeys[m.keyIndex]
	return createNextPass(tipID, tipHeader, m.txQueue, m.passStore, m.ledger, pubKey, m.memo)
}

// Called by the tracker as well as the peer to support get_work.
func createNextPass(tipID PassID, tipHeader *PassHeader, txQueue ConsiderationQueue,
	passStore PassStorage, ledger Ledger, pubKey ed25519.PublicKey, memo string) (*Pass, error) {

	// fetch considerations to confirm from the queue
	txs := txQueue.Get(MAX_CONSIDERATIONS_TO_INCLUDE_PER_PASS - 1)

	// calculate total pass point
	var newHeight int64 = tipHeader.Height + 1

	// build passpoint
	tx := NewConsideration(nil, pubKey, 0, 0, newHeight, memo)

	// prepend passpoint
	txs = append([]*Consideration{tx}, txs...)

	// compute the next target
	newTarget, err := computeTarget(tipHeader, passStore, ledger)
	if err != nil {
		return nil, err
	}

	// create the pass
	pass, err := NewPass(tipID, newHeight, newTarget, tipHeader.TrailWork, txs)
	if err != nil {
		return nil, err
	}
	return pass, nil
}

// Run executes the hashrate monitor's main loop in its own goroutine.
func (h *HashrateMonitor) Run() {
	h.wg.Add(1)
	go h.run()
}

func (h *HashrateMonitor) run() {
	defer h.wg.Done()

	var totalHashes int64
	updateInterval := 1 * time.Minute
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	for {
		select {
		case _, ok := <-h.shutdownChan:
			if !ok {
				log.Println("Hashrate monitor shutting down...")
				return
			}
		case hashes := <-h.hashUpdateChan:
			totalHashes += hashes
		case <-ticker.C:
			hps := float64(totalHashes) / updateInterval.Seconds()
			totalHashes = 0
			log.Printf("Hashrate: %.2f MH/s", hps/1000/1000)
		}
	}
}

// Shutdown stops the hashrate monitor synchronously.
func (h *HashrateMonitor) Shutdown() {
	close(h.shutdownChan)
	h.wg.Wait()
	log.Println("Hashrate monitor shutdown")
}
