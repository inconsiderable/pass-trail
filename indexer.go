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
	focales      *OrderedHashSet
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
		focales:      hashset,
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

// focaleIndex returns the index of a focale in the focaleEnumeration slice.
func focaleIndex(focale string, focaleEnumerations []string) int {
	for i, c := range focaleEnumerations {
		if c == focale {
			return i
		}
	}
	return -1
}

// generateStringsSlice returns a slice of strings where each element is the
// original string shortened by 2 characters from the end recursively.
func generateStringsSlice(s string) []string {
	// Base case: if the string is 2 characters, return a slice with just that string.
	if len(s) == 2 {
		return []string{s}
	}
	// Recursive case: append the current string to the result of the recursive call.
	return append([]string{s}, generateStringsSlice(s[:len(s)-2])...)
}

func focaleFromPubKey(pubKey string, focaleEnumerations []string) (Ok bool, Focale string, Catchments []string) {
	splitTrimmed := strings.Split(strings.TrimRight(pubKey, "/0="), "/")

	focalePrefix := splitTrimmed[0]

	if olc.CheckFull(focalePrefix) == nil {
		return true, focalePrefix, generateStringsSlice(strings.Split(focalePrefix, "+")[0])
	}

	focaleIndex, NAN_Err := strconv.Atoi(focalePrefix)
	if NAN_Err != nil {
		return false, "", nil
	}

	if len(focaleEnumerations) < (focaleIndex + 1) {
		return false, "", nil
	}

	if len(splitTrimmed) < 2 {
		return false, "", nil
	}

	focale := focaleEnumerations[focaleIndex]

	return true, focaleEnumerations[focaleIndex], generateStringsSlice(strings.Split(focale, "+")[0])
}

func inflateConsiderationNodes(pubKey string) (bool, string, []string, string) {

	trimmed := strings.TrimRight(pubKey, "/0=")
	splitPK := strings.Split(trimmed, "/")

	if len(splitPK) < 2 {
		return false, "", []string{}, ""
	}

	focale := splitPK[0]
	nodes := splitPK[1 : len(splitPK)-1] //ignore last node for replacing with the full pubKey later
	notes := splitPK[len(splitPK)-1]     //last node is the notes

	return true, focale, append(nodes, pubKey), notes
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

		/* Capture/enumerate focales */
		if con.By == nil {
			trimmedFor := strings.TrimRight(conFor, "0=")

			if err := olc.CheckFull(trimmedFor); err == nil {
				if increment {
					idx.focales.Add(trimmedFor)
				} else {
					forGraphIndex, ok := idx.txGraph.index[conFor]
					if ok {
						weight := idx.txGraph.edges[0][forGraphIndex]
						if weight < 2.0 {
							idx.focales.Remove(trimmedFor)
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

		if ok, focale, catchments := focaleFromPubKey(conFor, idx.focales.Values()); ok {
			if okk, _, nodes, notes := inflateConsiderationNodes(conFor); okk {

				focaleKey := padToBase64Length(focale)

				idx.txGraph.Link(conBy, focaleKey, incrementBy)
				idx.txGraph.Link(focaleKey, padToBase64Length(strings.Trim(nodes[0], "+")), incrementBy)

				for i, node := range nodes {
					if i == len(nodes)-1 {
						break //skip last node
					}
					trimmedNode := strings.Trim(node, "+")
					trimmedNextNode := strings.Trim(nodes[i+1], "+")

					idx.txGraph.Link(padToBase64Length(trimmedNode), padToBase64Length(trimmedNextNode), incrementBy)

					//if +prefix exists on node: isolate and link/return/refer back to the focal root for recovery
					if strings.HasPrefix(node, "+") {
						idx.txGraph.Link(padToBase64Length(trimmedNode), padToBase64Length("0"), incrementBy)
					}

					//Todo: if suffix+ exists on node: isolate and detour/defer onwards to the catchment area for discovery
				}

				if strings.HasPrefix(notes, "+") {
					idx.txGraph.Link(conFor, padToBase64Length("0"), incrementBy)
				}

				nts := strings.Split(strings.Trim(notes, "+"), "+")

				for _, note := range nts {
					idx.txGraph.Link(conFor, padToBase64Length(note), incrementBy)
					idx.txGraph.Link(padToBase64Length(note), padToBase64Length(catchments[0]), incrementBy)
				}

				for i, catchment := range catchments {
					if i == len(catchments)-1 {
						break //skip last catchment
					}
					idx.txGraph.Link(padToBase64Length(catchment), padToBase64Length(catchments[i+1]), incrementBy)
				}

				idx.txGraph.Link(padToBase64Length(catchments[len(catchments)-1]), padToBase64Length("0"), incrementBy)
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
