package passtrail

import (
	"fmt"
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
	focalPoints  *OrderedHashSet
	synonyms     map[string]string
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
	fpHashset := NewOrderedHashSet()
	fpHashset.Add(padTo44Characters("0"))
	return &Indexer{
		txGraph:      conGraph,
		passStore:    passStore,
		ledger:       ledger,
		processor:    processor,
		latestPassID: genesisPassID,
		latestHeight: 0,
		focalPoints:  fpHashset,
		synonyms:     make(map[string]string),
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
			idx.indexConsiderations(tip.Pass, tip.PassID, tip.Connect) //Todo: Make sure no consideration is skipped.
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

// focaleIndex returns the index of a focale in the focalePoints slice.
func focaleIndex(focale string, focalPoints []string) int {
	for i, c := range focalPoints {
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

func focaleFromPubKey(pubKey string, focalPoints []string) (Ok bool, Focale string, Catchments []string) {
	splitTrimmed := strings.Split(strings.TrimRight(pubKey, "/0="), "/")

	focaleNotation := strings.Trim(splitTrimmed[0], "+")

	if olc.CheckFull(focaleNotation) == nil {
		return true, focaleNotation, generateStringsSlice(strings.Split(focaleNotation, "+")[0])
	}

	focaleIndex, NAN_Err := strconv.Atoi(focaleNotation)
	if NAN_Err != nil {
		return false, "", nil
	}

	if len(focalPoints) < (focaleIndex + 1) {
		return false, "", nil
	}

	if len(splitTrimmed) < 2 {
		return false, "", nil
	}

	focale := focalPoints[focaleIndex]

	return true, focalPoints[focaleIndex], generateStringsSlice(strings.Split(focale, "+")[0])
}

func inflateNodes(pubKey string) (bool, string, []string, string) {

	trimmed := strings.TrimRight(pubKey, "/0=")
	splitPK := strings.Split(trimmed, "/")

	if len(splitPK) < 2 {
		return false, "", append([]string{}, pubKey), pubKey
	}

	focale := splitPK[0] //TODO: Parse if numeric to string focale
	nodes := splitPK
	notes := splitPK[len(splitPK)-1] //last node is the notes

	nodesOk := true

	if len(nodes) == 2 && strings.TrimRight(notes, "+") == "" {
		nodesOk = false
	}

	return nodesOk, focale, nodes, notes
}

func (idx *Indexer) rankGraph() {
	log.Printf("Indexer ranking at height: %d\n", idx.latestHeight)
	idx.txGraph.Rank(1.0, 1e-6)
	log.Printf("Ranking finished")
}

func (idx *Indexer) indexConsiderations(pass *Pass, id PassID, increment bool) {
	idx.latestPassID = id
	idx.latestHeight = pass.Header.Height

	incrementBy := 0.00

	if increment {
		incrementBy = 1
	} else {
		//Pass disconnected: Reverse all applicable considerations from the graph
		incrementBy = -1
	}

	for i := 0; i < len(pass.Considerations); i++ {
		con := pass.Considerations[i]

		conFor := pubKeyToString(con.For)
		conBy := pubKeyToString(con.By)

		idx.txGraph.Link(conBy, conFor, incrementBy/2)

		/* Capture/enumerate focales */
		if con.By == nil {
			trimmedFor := strings.TrimRight(conFor, "0=")

			if err := olc.CheckFull(trimmedFor); err == nil {
				if increment {
					idx.focalPoints.Add(trimmedFor)
				} else {
					forGraphIndex, ok := idx.txGraph.index[conFor]
					if ok {
						weight := idx.txGraph.edges[0][forGraphIndex]
						if weight < 2.0 {
							idx.focalPoints.Remove(trimmedFor)
						}
					}
				}
			}
		}

		nodesOk, focale, nodes, notes := inflateNodes(conFor)

		/*
			Capture synonyms for:
			"SenderKey" -> "/++++++++++++000000000000000000000000000000="
			   			-> "FOCALE+KEY/++++++++++++++000000000000000000="
			by capturing characters from Memo equal to number of "+".
		*/
		if strings.TrimRight(notes, "+") == "" && len(nodes) == 2 {
			subject := ""
			if focale == "" {
				subject = conBy //sender
			} else {
				subject = padTo44Characters(focale) //Capture focale synonyms
			}

			raw := fmt.Sprintf("%.*s", 15, con.Memo)
			idx.synonyms[subject] = strings.ReplaceAll(strings.Trim(strings.ToLower(raw), " "), " ", "-")
		}

		/*
			Build bifurcation graph (binary tree).
		*/
		if ok, focale, catchments := focaleFromPubKey(conFor, idx.focalPoints.Values()); ok && nodesOk {
			timestamp := time.Unix(con.Time, 0)
			idx.synonyms[conFor] = timestamp.UTC().Format(time.RFC822)

			focaleKey := padTo44Characters(focale)
			nts := strings.Split(strings.Trim(notes, "+"), "+")

			weight := incrementBy/2
			idx.txGraph.Link(conBy, focaleKey, weight)

			for i := 0; i < len(nodes); i++ {
				node := nodes[i]
				trimmedNode := strings.Trim(node, "+")

				key := padTo44Characters(trimmedNode)
				if i == 0 {
					key = focaleKey
				}
				if i == len(nodes)-1 {
					key = conFor
				}
				
				splitNode, rIntensity, lIntensity := strings.Split(node, trimmedNode), 1, 1
				
				if strings.HasSuffix(node, "+") {
					//if suffix+ exists on node: intensify the right
					rIntensity += len(splitNode[1])
				}

				if strings.HasPrefix(node, "+") {
					//if +prefix exists on node: intensify the left
					lIntensity += len(splitNode[0])
				}

				totalIntensity := rIntensity + lIntensity
				
				rWeight := (float64(rIntensity) / float64(totalIntensity)) * weight
				lWeight := weight - rWeight

				if j := i + 1; j < len(nodes) {
					next := nodes[j]
					trimmedNext := strings.Trim(next, "+")
					
					weight = idx.txGraph.Link(key, padTo44Characters(trimmedNext), rWeight)
					idx.txGraph.Link(key, padTo44Characters(catchments[len(catchments) - j]), lWeight)//Todo: if catchments < nodes
				}

				if i == len(nodes)-1 {//last node
					passHeight := padTo44Characters(strconv.FormatInt(pass.Header.Height, 10) + "/")
					prevHeight := padTo44Characters(strconv.FormatInt(pass.Header.Height-1, 10) + "/")

					for k := 0; k < len(nts); k++ {
						note := nts[k]
						nweight := idx.txGraph.Link(key, padTo44Characters(note), rWeight/float64(len(nts)))
						idx.txGraph.Link(padTo44Characters(note), padTo44Characters(passHeight), nweight/2)
					}
					idx.txGraph.Link(key, padTo44Characters(passHeight), lWeight)//+ nWeight/2

					idx.txGraph.Link(padTo44Characters(passHeight), padTo44Characters(prevHeight), lWeight/2)//+ nWeight/2
					idx.txGraph.Link(padTo44Characters(passHeight), padTo44Characters("0"), lWeight/2)//+ nWeight/2
				}
			}
		}
	}
}

// Shutdown stops the indexer synchronously.
func (idx *Indexer) Shutdown() {
	close(idx.shutdownChan)
	idx.wg.Wait()
	log.Printf("Indexer shutdown\n")
}
