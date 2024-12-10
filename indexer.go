package focalpoint

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
	viewStore    ViewStorage
	ledger       Ledger
	processor    *Processor
	latestViewID ViewID
	latestHeight int64
	cnGraph      *Graph
	Indices  	 *OrderedHashSet
	synonyms     map[string]string
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

func NewIndexer(
	conGraph *Graph,
	viewStore ViewStorage,
	ledger Ledger,
	processor *Processor,
	genesisViewID ViewID,
) *Indexer {
	fpHashset := NewOrderedHashSet()
	fpHashset.Add(padTo44Characters("0"))
	return &Indexer{
		cnGraph:      conGraph,
		viewStore:    viewStore,
		ledger:       ledger,
		processor:    processor,
		latestViewID: genesisViewID,
		latestHeight: 0,
		Indices:  	  fpHashset,
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
	ibd, _, err := IsInitialViewDownload(idx.ledger, idx.viewStore)
	if err != nil {
		panic(err)
	}
	if ibd {
		log.Printf("Indexer waiting for focalpoint sync\n")
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
				ibd, _, err = IsInitialViewDownload(idx.ledger, idx.viewStore)
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

	header, _, err := idx.viewStore.GetViewHeader(idx.latestViewID)
	if err != nil {
		log.Println(err)
		return
	}
	if header == nil {
		// don't have it
		log.Println(err)
		return
	}
	branchType, err := idx.ledger.GetBranchType(idx.latestViewID)
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
		nextID, err := idx.ledger.GetViewIDForHeight(height)
		if err != nil {
			log.Println(err)
			return
		}
		if nextID == nil {
			height -= 1
			break
		}

		view, err := idx.viewStore.GetView(*nextID)
		if err != nil {
			// not found
			log.Println(err)
			return
		}

		if view == nil {
			// not found
			log.Printf("No view found with ID %v", nextID)
			return
		}

		idx.indexConsiderations(view, *nextID, true)

		height += 1
	}

	log.Printf("Finished indexing at height %v", idx.latestHeight)
	log.Printf("Latest indexed viewID: %v", idx.latestViewID)

	idx.rankGraph()

	// register for tip changes
	tipChangeChan := make(chan TipChange, 1)
	idx.processor.RegisterForTipChange(tipChangeChan)
	defer idx.processor.UnregisterForTipChange(tipChangeChan)

	for {
		select {
		case tip := <-tipChangeChan:
			log.Printf("Indexer received notice of new tip view: %s at height: %d\n", tip.ViewID, tip.View.Header.Height)
			idx.indexConsiderations(tip.View, tip.ViewID, tip.Connect) //Todo: Make sure no consideration is skipped.
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

// localeIndex returns the index of a locale in the localePoints slice.
func localeIndex(locale string, indices []string) int {
	for i, c := range indices {
		if c == locale {
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

func localeFromPubKey(pubKey string, focalPoints []string) (Ok bool, Locale string, Catchments []string) {
	splitTrimmed := strings.Split(strings.TrimRight(pubKey, "/0="), "/")

	localeNotation := strings.Trim(splitTrimmed[0], "+")

	if olc.CheckFull(localeNotation) == nil {
		return true, localeNotation, generateStringsSlice(strings.Split(localeNotation, "+")[0])
	}

	localeIndex, NAN_Err := strconv.Atoi(localeNotation)
	if NAN_Err != nil {
		return false, "", nil
	}

	if len(focalPoints) < (localeIndex + 1) {
		return false, "", nil
	}

	if len(splitTrimmed) < 2 {
		return false, "", nil
	}

	locale := focalPoints[localeIndex]

	return true, focalPoints[localeIndex], generateStringsSlice(strings.Split(locale, "+")[0])
}

func inflateNodes(pubKey string) (bool, string, []string, string) {

	trimmed := strings.TrimRight(pubKey, "/0=")
	splitPK := strings.Split(trimmed, "/")

	if len(splitPK) < 2 {
		return false, "", append([]string{}, pubKey), pubKey
	}

	locale := splitPK[0]              //TODO: Parse if numeric to string locale
	nodes := splitPK[:len(splitPK)-1] //all nodes except the last one
	notes := splitPK[len(splitPK)-1]  //last node is the notes

	nodesOk := true

	if len(nodes) == 1 && strings.TrimRight(notes, "+") == "" {
		nodesOk = false
	}

	return nodesOk, locale, nodes, notes
}

func (idx *Indexer) rankGraph() {
	log.Printf("Indexer ranking at height: %d\n", idx.latestHeight)
	idx.cnGraph.Rank(1.0, 1e-6)
	log.Printf("Ranking finished")
}

func (idx *Indexer) indexConsiderations(view *View, id ViewID, increment bool) {
	idx.latestViewID = id
	idx.latestHeight = view.Header.Height
	incrementBy := 0.00

	if increment {
		incrementBy = 1
	} else {
		//View disconnected: Reverse all applicable considerations from the graph
		incrementBy = -1
	}

	for c := 0; c < len(view.Considerations); c++ {
		con := view.Considerations[c]

		conFor := pubKeyToString(con.For)
		conBy := pubKeyToString(con.By)

		nodesOk, locale, nodes, notes := inflateNodes(conFor)

		/* 
			Capture/enumerate (bookmarks?)
			6FG22222+222/201/window00000000000000000000=
		*/
		if con.By == nil && nodesOk {
			trimmedFor := strings.TrimRight(conFor, "/0=")

			if err := olc.CheckFull(locale); err == nil {
				if increment {
					idx.Indices.Add(trimmedFor)
				} else {
					forGraphIndex, ok := idx.cnGraph.index[conFor]
					if ok {
						weight := idx.cnGraph.edges[0][forGraphIndex]
						if weight < 2.0 {
							idx.Indices.Remove(trimmedFor)
						}
					}
				}
			}
		}

		/*
			Capture synonyms for:
			"SenderKey" -> "/+00000000000000000000000000000000000000000="
						-> "6FG22222+222/+00000000000000000000000000000="
			by capturing characters from Memo equal to number of "+".
		*/
		if strings.TrimRight(notes, "+") == "" && len(nodes) == 1 {
			subject := ""
			if locale == "" {
				subject = conBy //sender
			} else {
				subject = padTo44Characters(locale) //Capture locale synonyms
			}

			raw := fmt.Sprintf("%.*s", 15, con.Memo)
			idx.synonyms[subject] = strings.ReplaceAll(strings.Trim(strings.ToLower(raw), " "), " ", "-")
		}

		idx.cnGraph.Link(conBy, conFor, incrementBy)

		viewHeight := strconv.FormatInt(view.Header.Height, 10) + "+"

		/*
			Build graph.
		*/
		if ok, locale, catchments := localeFromPubKey(conFor, idx.Indices.Values()); ok && nodesOk {
			
			idx.cnGraph.Link(conFor, viewHeight, incrementBy/2)//l1

			timestamp := time.Unix(con.Time, 0)
			idx.synonyms[conFor] = timestamp.UTC().Format("2006/01/02 15:04:05")

			YEAR := timestamp.UTC().Format("2006+")
			MONTH := timestamp.UTC().Format("2006/01+")
			DAY := timestamp.UTC().Format("2006/01/02+")

			idx.cnGraph.Link(conFor, DAY, incrementBy/4)
			idx.cnGraph.Link(DAY, MONTH, incrementBy/4)
			idx.cnGraph.Link(MONTH, YEAR, incrementBy/4)
			idx.cnGraph.Link(YEAR, "0", incrementBy/4)

			
			weight := (incrementBy/2) / float64(len(nodes)+1)

			reversedNodes := reverse(nodes)

			nts := strings.Split(strings.Trim(notes, "+"), "+")
			for k := 0; k < len(nts); k++ {
				nweight := weight/float64(len(nts))
				
				idx.cnGraph.Link(conFor, nts[k], nweight)
				idx.cnGraph.Link(nts[k], reversedNodes[0], nweight)
			}

			for i := 0; i < len(reversedNodes); i++ {
				node := reversedNodes[i]
				trimmedNode := strings.Trim(node, "+")
				trimmedNodeKey := trimmedNode

				idx.cnGraph.Link(conFor, trimmedNodeKey, weight)

				if i == len(reversedNodes)-1 {
					trimmedNodeKey = locale
					idx.cnGraph.Link(trimmedNodeKey, catchments[0], weight)
				}

				if j := i + 1; j < len(reversedNodes) {
					next := reversedNodes[j]
					trimmedNext := strings.Trim(next, "+")

					trimmedNextKey := trimmedNext

					if j == len(reversedNodes)-1 {
						trimmedNextKey = locale
					}

					/*
						6FG22222+222/+201/window+/porous+broken0000=
					*/

					// splitNode, rIntensity, lIntensity := strings.Split(node, trimmedNode), 1, 1

					// if strings.HasPrefix(node, "+") {
					// 	//+prefix on node: refer, return to focal origin
					// 	//lIntensity += len(splitNode[0])
					// 	idx.cnGraph.Link(trimmedNode, "0", incrementBy)
					// }

					// if strings.HasSuffix(node, "+") {
					// 	//suffix+ on node: defer, deturn to focal destination
					// 	//rIntensity += len(splitNode[1])
					// 	idx.cnGraph.Link(trimmedNode, viewHeight, incrementBy)
					// }

					idx.cnGraph.Link(trimmedNodeKey, trimmedNextKey, weight)
				}
			}

			for i := 0; i < len(catchments); i++ {
				if j := i + 1; j < len(catchments) {
					idx.cnGraph.Link(catchments[i], catchments[j], weight)
				}

				if i == len(catchments)-1 {
					idx.cnGraph.Link(catchments[i], "0", weight)
				}
			}			
			
			orders := DiminishingOrders(view.Header.Height)

			for j := 1; j < len(orders); j++ {
				i := j - 1

				source := strconv.FormatInt(orders[i], 10) + "+"
				target := strconv.FormatInt(orders[j], 10)

				if orders[j] != 0 {
					target = target + "+"
				}

				idx.cnGraph.Link(source, target, incrementBy/2)
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
