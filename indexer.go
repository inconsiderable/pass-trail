package passtrail

import (
	"fmt"
	"log"
	"math"
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

	focale := splitPK[0]              //TODO: Parse if numeric to string focale
	nodes := splitPK[:len(splitPK)-1] //all nodes except the last one
	notes := splitPK[len(splitPK)-1]  //last node is the notes

	nodesOk := true

	if len(nodes) == 1 && strings.TrimRight(notes, "+") == "" {
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

	for c := 0; c < len(pass.Considerations); c++ {
		con := pass.Considerations[c]

		conFor := pubKeyToString(con.For)
		conBy := pubKeyToString(con.By)

		/* Capture/enumerate focales */
		if con.By == nil {
			trimmedFor := strings.TrimRight(conFor, "/0=")

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
		if strings.TrimRight(notes, "+") == "" && len(nodes) == 1 {
			subject := ""
			if focale == "" {
				subject = conBy //sender
			} else {
				subject = padTo44Characters(focale) //Capture focale synonyms
			}

			raw := fmt.Sprintf("%.*s", 15, con.Memo)
			idx.synonyms[subject] = strings.ReplaceAll(strings.Trim(strings.ToLower(raw), " "), " ", "-")
		}

		idx.txGraph.Link(conBy, conFor, incrementBy)

		passHeight := strconv.FormatInt(pass.Header.Height, 10) + "/+"

		/*
			Build bifurcation graph (binary tree).
		*/
		if ok, focale, catchments := focaleFromPubKey(conFor, idx.focalPoints.Values()); ok && nodesOk {
			
			idx.txGraph.Link(conFor, passHeight, incrementBy/2)//l1

			timestamp := time.Unix(con.Time, 0)
			idx.synonyms[conFor] = timestamp.UTC().Format("2006-01-02 15:04:05")

			YEAR := timestamp.UTC().Format("2006")
			MONTH := timestamp.UTC().Format("2006+01")
			DAY := timestamp.UTC().Format("2006+01+02")

			idx.txGraph.Link(conFor, DAY, incrementBy/4)
			idx.txGraph.Link(DAY, MONTH, incrementBy/4)
			idx.txGraph.Link(MONTH, YEAR, incrementBy/4)
			idx.txGraph.Link(YEAR, "0", incrementBy/4)

			
			weight := (incrementBy/2) / float64(len(nodes)+1)

			reversedNodes := reverse(nodes)

			nts := strings.Split(strings.Trim(notes, "+"), "+")
			for k := 0; k < len(nts); k++ {
				nweight := weight/float64(len(nts))
				
				idx.txGraph.Link(conFor, nts[k], nweight)
				idx.txGraph.Link(nts[k], reversedNodes[0], nweight)
			}

			for i := 0; i < len(reversedNodes); i++ {
				node := reversedNodes[i]
				trimmedNode := strings.Trim(node, "+")
				trimmedNodeKey := trimmedNode

				idx.txGraph.Link(conFor, trimmedNodeKey, weight)

				if i == len(reversedNodes)-1 {
					trimmedNodeKey = focale
					idx.txGraph.Link(trimmedNodeKey, catchments[0], weight)
				}

				if j := i + 1; j < len(reversedNodes) {
					next := reversedNodes[j]
					trimmedNext := strings.Trim(next, "+")

					trimmedNextKey := trimmedNext

					if j == len(reversedNodes)-1 {
						trimmedNextKey = focale
					}

					// splitNode, rIntensity, lIntensity := strings.Split(node, trimmedNode), 1, 1

					// totalIntensity := rIntensity + lIntensity

					// reWeight := (float64(rIntensity) / float64(totalIntensity)) * weight/2
					// goWeight := (float64(lIntensity) / float64(totalIntensity)) * weight/2

					// if strings.HasPrefix(node, "+") {
					// 	//+prefix on node: refer, return to focal origin
					// 	//lIntensity += len(splitNode[0])
					// 	idx.txGraph.Link(trimmedNode, "0", incrementBy)
					// }

					// if strings.HasSuffix(node, "+") {
					// 	//suffix+ on node: defer, deturn to focal destination
					// 	//rIntensity += len(splitNode[1])
					// 	idx.txGraph.Link(trimmedNode, passHeight, incrementBy)
					// }

					idx.txGraph.Link(trimmedNodeKey, trimmedNextKey, weight)
				}
			}

			for i := 0; i < len(catchments); i++ {
				if j := i + 1; j < len(catchments) {
					idx.txGraph.Link(catchments[i], catchments[j], weight)
				}

				if i == len(catchments)-1 {
					idx.txGraph.Link(catchments[i], "0", weight)
				}
			}			
			
			orders := DiminishingOrders(pass.Header.Height)

			for j := 1; j < len(orders); j++ {
				i := j - 1

				source := strconv.FormatInt(orders[i], 10) + "/+"
				target := strconv.FormatInt(orders[j], 10)

				if orders[j] != 0 {
					target = target + "/+"
				}

				idx.txGraph.Link(source, target, incrementBy/2)
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

func DiminishingOrders(n int64) []int64 {
	// Special-case zero.
	if n == 0 {
		return []int64{0}
	}
	// Determine the number of digits.
	digits := int(math.Log10(float64(n))) + 1

	results := []int64{n}
	// For each power of 10 from 10^1 up to 10^(digits)
	for i := 0; i < digits; i++ {
		power := int64(math.Pow(10, float64(i+1)))
		rounded := n - (n % power)
		// Append only if it's a new value
		if rounded != results[len(results)-1] {
			results = append(results, rounded)
		}
	}
	return results
}

func reverse(s []string) []string {
	result := make([]string, len(s))
	for i, v := range s {
		result[len(s)-1-i] = v
	}
	return result
}
