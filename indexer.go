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

	focalePrefix := splitTrimmed[0]

	if olc.CheckFull(focalePrefix) == nil {
		return true, focalePrefix, generateStringsSlice(strings.Split(focalePrefix, "+")[0])
	}

	focaleIndex, NAN_Err := strconv.Atoi(focalePrefix)
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
		//Pass disconnected
		//TODO: Remove all considerations from the graph
		incrementBy = -1
	}

	passHeight := strconv.FormatInt(pass.Header.Height, 10)
	passWeight := 0.0

	idx.txGraph.Rename(padTo44Characters("0"), padTo44Characters(passHeight+"/"))//shed old self: reset and archive

	for i := 0; i < len(pass.Considerations); i++ {
		weight := incrementBy
		con := pass.Considerations[i]

		conFor := pubKeyToString(con.For)
		conBy := pubKeyToString(con.By)

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

			raw := fmt.Sprintf("%.*s", len(notes), con.Memo)
			idx.synonyms[subject] = strings.ReplaceAll(raw, " ", "-")

		}

		/*
			Capture consideration tree/graph
		*/
		if ok, focale, catchments := focaleFromPubKey(conFor, idx.focalPoints.Values()); ok && nodesOk {
			timestamp := time.Unix(con.Time, 0)
			idx.synonyms[conFor] = timestamp.UTC().Format(time.RFC822)

			catchmentRoot := catchments[len(catchments)-1]
			focaleKey := padTo44Characters(focale)
			nts := strings.Split(strings.Trim(notes, "+"), "+")

			weight = weight/2
			localWeight := weight
			idx.txGraph.Link(conBy, focaleKey, localWeight)

			totalIndividualNoteWeight := 0.0

			for i := 0; i < len(nodes); i++ {
				node := nodes[i]
				trimmedNode := strings.Trim(node, "+")

				if i == 0 { //first is always focale
					node = focale
					trimmedNode = focaleKey
				}

				if i == len(nodes)-1 { //last is always conFor
					trimmedNode = conFor
				}

				localWeight = localWeight / float64(len(nodes)-i)

				splitNode := strings.Split(node, trimmedNode)

				if strings.HasPrefix(node, "+") {
					//if +prefix exists on node: isolate and refer/return back to the focal root for recovery
					intensity := len(splitNode[0])
					factor := localWeight / float64(intensity+1)
					idx.txGraph.Link(padTo44Characters(trimmedNode), padTo44Characters("0"), factor*float64(intensity))
				}

				if strings.HasSuffix(node, "+") {
					//if suffix+ exists on node: isolate and defer/deturn onwards to the catchment area for discovery
					intensity := len(splitNode[1])
					factor := localWeight / float64(intensity+1)
					idx.txGraph.Link(padTo44Characters(trimmedNode), padTo44Characters(catchmentRoot), factor*float64(intensity))
				}

				for j := i + 1; j < len(nodes); j++ {
					next := nodes[j]
					trimmedNext := strings.Trim(next, "+")
					if j == len(nodes)-1 {
						trimmedNext = conFor
					}

					idx.txGraph.Link(padTo44Characters(trimmedNode), padTo44Characters(trimmedNext), localWeight)
				}

				noteWeight := localWeight / float64(len(nts))

				for k := 0; k < len(nts); k++ {
					note := nts[k]
					idx.txGraph.Link(padTo44Characters(trimmedNode), padTo44Characters(note), noteWeight)
				}

				totalIndividualNoteWeight = noteWeight + totalIndividualNoteWeight
			}

			catchmentWeight := totalIndividualNoteWeight / float64(len(catchments)+1) //1 share for self.

			totalCatchmentRootWeight := 0.0

			for _, note := range nts {

				diminishingWeight := catchmentWeight

				for i := 0; i < len(catchments); i++ {
					idx.txGraph.Link(padTo44Characters(note), padTo44Characters(catchments[i]), catchmentWeight)
					totalCatchmentRootWeight = totalCatchmentRootWeight + catchmentWeight

					diminishingWeight = diminishingWeight / float64(len(catchments)-i)

					for j := i + 1; j < len(catchments); j++ {
						idx.txGraph.Link(padTo44Characters(catchments[i]), padTo44Characters(catchments[j]), diminishingWeight)
						totalCatchmentRootWeight = totalCatchmentRootWeight + diminishingWeight
					}
				}
			}

			idx.txGraph.Link(padTo44Characters(catchmentRoot), padTo44Characters("0"), totalCatchmentRootWeight/2)
		}
		

		idx.txGraph.Link(conBy, conFor, weight)
		idx.txGraph.Link(conFor, padTo44Characters(passHeight+"/"), weight/2)
		passWeight = passWeight + (weight/2)		
	}	

	idx.txGraph.Link(padTo44Characters(passHeight+"/"), padTo44Characters("0"), passWeight/2)
}

// Shutdown stops the indexer synchronously.
func (idx *Indexer) Shutdown() {
	close(idx.shutdownChan)
	idx.wg.Wait()
	log.Printf("Indexer shutdown\n")
}
