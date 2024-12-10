package passtrail

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	olc "github.com/google/open-location-code/go"
)

type Indexer struct {
	passStore    PassStorage
	ledger       Ledger
	processor    *Processor
	latestPassID PassID
	latestHeight int64
	txGraph      *Graph
	catchments   *OrderedHashSet
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

func NewIndexer(
	conGraph *Graph,
	passStore PassStorage,
	ledger Ledger,
	processor *Processor,
	genesisPassID PassID,
) *Indexer {
	hashset := NewOrderedHashSet()
	hashset.Add(padToBase64Length("0"))
	return &Indexer{
		txGraph:      conGraph,
		passStore:    passStore,
		ledger:       ledger,
		processor:    processor,
		latestPassID: genesisPassID,
		latestHeight: 0,
		catchments:   hashset,
		shutdownChan: make(chan struct{}),
	}
}

// Run executes the indexer's main loop in its own goroutine.
func (idx *Indexer) Run() {
	idx.wg.Add(1)
	go idx.run()
}

func (idx *Indexer) run() {
	defer idx.wg.Done()

	ticker := time.NewTicker(30 * time.Second)

	// don't start indexing until we think we're synced.
	// we're just wasting time and slowing down the sync otherwise
	ibd, _, err := IsInitialPassDownload(idx.ledger, idx.passStore)
	if err != nil {
		panic(err)
	}
	if ibd {
		log.Printf("Indexer waiting for passtrail sync\n")
	ready:
		for {
			select {
			case _, ok := <-idx.shutdownChan:
				if !ok {
					log.Printf("Indexer shutting down...\n")
					return
				}
			case <-ticker.C:
				var err error
				ibd, _, err = IsInitialPassDownload(idx.ledger, idx.passStore)
				if err != nil {
					panic(err)
				}
				if !ibd {
					// time to start indexing
					break ready
				}
			}
		}
	}

	ticker.Stop()

	header, _, err := idx.passStore.GetPassHeader(idx.latestPassID)
	if err != nil {
		log.Println(err)
		return
	}
	if header == nil {
		// don't have it
		log.Println(err)
		return
	}
	branchType, err := idx.ledger.GetBranchType(idx.latestPassID)
	if err != nil {
		log.Println(err)
		return
	}
	if branchType != MAIN {
		// not on the main branch
		log.Println(err)
		return
	}

	var height int64 = header.Height
	for {
		nextID, err := idx.ledger.GetPassIDForHeight(height)
		if err != nil {
			log.Println(err)
			return
		}
		if nextID == nil {
			height -= 1
			break
		}

		pass, err := idx.passStore.GetPass(*nextID)
		if err != nil {
			// not found
			log.Println(err)
			return
		}

		if pass == nil {
			// not found
			log.Printf("No pass found with ID %v", nextID)
			return
		}

		idx.indexConsiderations(pass, *nextID, true)

		height += 1
	}

	log.Printf("Finished indexing at height %v", idx.latestHeight)
	log.Printf("Latest indexed passID: %v", idx.latestPassID)

	idx.rankGraph()

	// register for tip changes
	tipChangeChan := make(chan TipChange, 1)
	idx.processor.RegisterForTipChange(tipChangeChan)
	defer idx.processor.UnregisterForTipChange(tipChangeChan)

	for {
		select {
		case tip := <-tipChangeChan:
			log.Printf("Indexer received notice of new tip pass: %s at height: %d\n", tip.PassID, tip.Pass.Header.Height)
			idx.indexConsiderations(tip.Pass, tip.PassID, tip.Connect) //Todo: Does this capture every last consideration?
			if !tip.More {
				idx.rankGraph()
			}
		case _, ok := <-idx.shutdownChan:
			if !ok {
				log.Printf("Indexer shutting down...\n")
				return
			}
		}
	}
}

// catchmentIndex returns the index of a catchment in the catchments slice.
func catchmentIndex(catchment string, catchments []string) int {
	for i, c := range catchments {
		if c == catchment {
			return i
		}
	}
	return -1
}

func catchmentFromPubKey(pubKey string, catchments []string) (bool, string) {
	splitTrimmed := strings.Split(strings.TrimRight(pubKey, "/0="), "/")

	catchment := splitTrimmed[0]

	if olc.CheckFull(catchment) == nil {
		return true, catchment
	}

	catchmentIndex, NAN_Err := strconv.Atoi(catchment)
	if NAN_Err != nil {
		return false, ""
	}

	if len(catchments) < (catchmentIndex + 1) {
		return false, ""
	}

	if len(splitTrimmed) < 2 {
		return false, ""
	}

	return true, catchments[catchmentIndex]
}

func inflateConsiderationNodes(pubKey string) (bool, string, []string, string) {

	trimmed := strings.TrimRight(pubKey, "/0=")
	splitPK := strings.Split(trimmed, "/")

	if len(splitPK) < 2 {
		return false, "", []string{}, ""
	}
	
	catchment := splitPK[0]
	nodes := splitPK[1:len(splitPK)-1] //ignore last node for replacing with the full pubKey later
	notes := splitPK[len(splitPK)-1] //last node is the notes

	return true, catchment, append(nodes, pubKey), notes
}

func (idx *Indexer) rankGraph() {
	log.Printf("Indexer ranking at height: %d\n", idx.latestHeight)
	idx.txGraph.Rank(1.0, 1e-6)
	log.Printf("Ranking finished")
}

func (idx *Indexer) indexConsiderations(pass *Pass, id PassID, increment bool) {
	idx.latestPassID = id
	idx.latestHeight = pass.Header.Height

	for i := 0; i < len(pass.Considerations); i++ {
		con := pass.Considerations[i]

		conFor := pubKeyToString(con.For)
		conBy := pubKeyToString(con.By)

		/* Capture catchments */
		if con.By == nil {
			trimmedFor := strings.TrimRight(conFor, "0=")

			if err := olc.CheckFull(trimmedFor); err == nil {
				if increment {
					idx.catchments.Add(trimmedFor)
				} else {
					forGraphIndex, ok := idx.txGraph.index[conFor]
					if ok {
						weight := idx.txGraph.edges[0][forGraphIndex]
						if weight < 2.0 {
							idx.catchments.Remove(trimmedFor)
						}
					}
				}
			}
		}

		incrementBy := 0.00

		if increment {
			incrementBy = 1
		} else {
			incrementBy = -1 //Pass disconnect
		}

		if ok, catchment := catchmentFromPubKey(conFor, idx.catchments.Values()); ok {
			if okk, _, nodes, notes := inflateConsiderationNodes(conFor); okk {

				catchKey := padToBase64Length(catchment)

				idx.txGraph.Link(conBy, catchKey, incrementBy)
				idx.txGraph.Link(catchKey, padToBase64Length(strings.Trim(nodes[0], "+")), incrementBy)

				for i, node := range nodes {
					if i == len(nodes)-1 {
						break //skip last node
					}
					trimmedNode := strings.Trim(node, "+")
					trimmedNextNode := strings.Trim(nodes[i+1], "+")

					idx.txGraph.Link(padToBase64Length(trimmedNode), padToBase64Length(trimmedNextNode), incrementBy)

					//if +prefix exists on node: isolate and link back to the catchment root for discovery
					if strings.HasPrefix(node, "+") {
						idx.txGraph.Link(padToBase64Length(trimmedNode), padToBase64Length("0"), incrementBy)
					}
				}

				if strings.HasPrefix(notes, "+") {
					idx.txGraph.Link(conFor, padToBase64Length("0"), incrementBy)
				}

				nts := strings.Split(strings.Trim(notes, "+"), "+")

				for _, note := range nts {
					idx.txGraph.Link(conFor, padToBase64Length(note), incrementBy)
					idx.txGraph.Link(padToBase64Length(note), padToBase64Length("0"), incrementBy)
				}
			} else {
				idx.txGraph.Link(conBy, conFor, incrementBy)
			}

		} else {
			idx.txGraph.Link(conBy, conFor, incrementBy)
		}
	}
}

// Shutdown stops the indexer synchronously.
func (idx *Indexer) Shutdown() {
	close(idx.shutdownChan)
	idx.wg.Wait()
	log.Printf("Indexer shutdown\n")
}
