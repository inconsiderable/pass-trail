package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	. "github.com/inconsiderable/pass-trail"
	"github.com/logrusorgru/aurora"
	"golang.org/x/crypto/ed25519"
)

// A small tool to inspect the pass trail and ledger offline
func main() {
	var commands = []string{
		"height", "imbalance", "imbalance_at", "pass", "pass_at", "tx", "history", "verify",
	}

	dataDirPtr := flag.String("datadir", "", "Path to a directory containing pass trail data")
	pubKeyPtr := flag.String("pubkey", "", "Base64 encoded public key")
	cmdPtr := flag.String("command", "height", "Commands: "+strings.Join(commands, ", "))
	heightPtr := flag.Int("height", 0, "Pass trail height")
	passIDPtr := flag.String("pass_id", "", "Pass ID")
	txIDPtr := flag.String("tx_id", "", "Consideration ID")
	startHeightPtr := flag.Int("start_height", 0, "Start pass height (for use with \"history\")")
	startIndexPtr := flag.Int("start_index", 0, "Start consideration index (for use with \"history\")")
	endHeightPtr := flag.Int("end_height", 0, "End pass height (for use with \"history\")")
	limitPtr := flag.Int("limit", 3, "Limit (for use with \"history\")")
	flag.Parse()

	if len(*dataDirPtr) == 0 {
		log.Printf("You must specify a -datadir\n")
		os.Exit(-1)
	}

	var pubKey ed25519.PublicKey
	if len(*pubKeyPtr) != 0 {
		// decode the key
		pubKeyBytes, err := base64.StdEncoding.DecodeString(*pubKeyPtr)
		if err != nil {
			log.Fatal(err)
		}
		pubKey = ed25519.PublicKey(pubKeyBytes)
	}

	var passID *PassID
	if len(*passIDPtr) != 0 {
		passIDBytes, err := hex.DecodeString(*passIDPtr)
		if err != nil {
			log.Fatal(err)
		}
		passID = new(PassID)
		copy(passID[:], passIDBytes)
	}

	var txID *ConsiderationID
	if len(*txIDPtr) != 0 {
		txIDBytes, err := hex.DecodeString(*txIDPtr)
		if err != nil {
			log.Fatal(err)
		}
		txID = new(ConsiderationID)
		copy(txID[:], txIDBytes)
	}

	// instatiate pass storage (read-only)
	passStore, err := NewPassStorageDisk(
		filepath.Join(*dataDirPtr, "passes"),
		filepath.Join(*dataDirPtr, "headers.db"),
		true,  // read-only
		false, // compress (if a pass is compressed storage will figure it out)
	)
	if err != nil {
		log.Fatal(err)
	}

	// instantiate the ledger (read-only)
	ledger, err := NewLedgerDisk(filepath.Join(*dataDirPtr, "ledger.db"),
		true,  // read-only
		false, // prune (no effect with read-only set)
		passStore,
	    NewGraph())
		
	if err != nil {
		log.Fatal(err)
	}

	// get the current height
	_, currentHeight, err := ledger.GetTrailTip()
	if err != nil {
		log.Fatal(err)
	}

	switch *cmdPtr {
	case "height":
		log.Printf("Current pass trail height is: %d\n", aurora.Bold(currentHeight))

	case "imbalance":
		if pubKey == nil {
			log.Fatal("-pubkey required for \"imbalance\" command")
		}
		imbalance, err := ledger.GetPublicKeyImbalance(pubKey)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Current imbalance: %+d\n", aurora.Bold(imbalance))

	case "imbalance_at":
		if pubKey == nil {
			log.Fatal("-pubkey required for \"imbalance_at\" command")
		}
		imbalance, err := ledger.GetPublicKeyImbalanceAt(pubKey, int64(*heightPtr))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Imbalance at height %d: %+d\n", *heightPtr, aurora.Bold(imbalance))

	case "pass_at":
		id, err := ledger.GetPassIDForHeight(int64(*heightPtr))
		if err != nil {
			log.Fatal(err)
		}
		if id == nil {
			log.Fatalf("No pass found at height %d\n", *heightPtr)
		}
		pass, err := passStore.GetPass(*id)
		if err != nil {
			log.Fatal(err)
		}
		if pass == nil {
			log.Fatalf("No pass with ID %s\n", *id)
		}
		displayPass(*id, pass)

	case "pass":
		if passID == nil {
			log.Fatalf("-pass_id required for \"pass\" command")
		}
		pass, err := passStore.GetPass(*passID)
		if err != nil {
			log.Fatal(err)
		}
		if pass == nil {
			log.Fatalf("No pass with id %s\n", *passID)
		}
		displayPass(*passID, pass)

	case "tx":
		if txID == nil {
			log.Fatalf("-tx_id required for \"tx\" command")
		}
		id, index, err := ledger.GetConsiderationIndex(*txID)
		if err != nil {
			log.Fatal(err)
		}
		if id == nil {
			log.Fatalf("Consideration %s not found", *txID)
		}
		tx, header, err := passStore.GetConsideration(*id, index)
		if err != nil {
			log.Fatal(err)
		}
		if tx == nil {
			log.Fatalf("No consideration found with ID %s\n", *txID)
		}
		displayConsideration(*txID, header, index, tx)

	case "history":
		if pubKey == nil {
			log.Fatal("-pubkey required for \"history\" command")
		}
		bIDs, indices, stopHeight, stopIndex, err := ledger.GetPublicKeyConsiderationIndicesRange(
			pubKey, int64(*startHeightPtr), int64(*endHeightPtr), int(*startIndexPtr), int(*limitPtr))
		if err != nil {
			log.Fatal(err)
		}
		displayHistory(bIDs, indices, stopHeight, stopIndex, passStore)

	case "verify":
		verify(ledger, passStore, pubKey, currentHeight)
	}

	// close storage
	if err := passStore.Close(); err != nil {
		log.Println(err)
	}
	if err := ledger.Close(); err != nil {
		log.Println(err)
	}
}

type concisePass struct {
	ID           PassID         `json:"id"`
	Header       PassHeader     `json:"header"`
	Considerations []ConsiderationID `json:"considerations"`
}

func displayPass(id PassID, pass *Pass) {
	b := concisePass{
		ID:           id,
		Header:       *pass.Header,
		Considerations: make([]ConsiderationID, len(pass.Considerations)),
	}

	for i := 0; i < len(pass.Considerations); i++ {
		txID, err := pass.Considerations[i].ID()
		if err != nil {
			panic(err)
		}
		b.Considerations[i] = txID
	}

	bJson, err := json.MarshalIndent(&b, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bJson))
}

type txWithContext struct {
	PassID     PassID       `json:"pass_id"`
	PassHeader PassHeader   `json:"pass_header"`
	TxIndex     int           `json:"consideration_index_in_pass"`
	ID          ConsiderationID `json:"consideration_id"`
	Consideration *Consideration  `json:"consideration"`
}

func displayConsideration(txID ConsiderationID, header *PassHeader, index int, tx *Consideration) {
	passID, err := header.ID()
	if err != nil {
		panic(err)
	}

	t := txWithContext{
		PassID:     passID,
		PassHeader: *header,
		TxIndex:     index,
		ID:          txID,
		Consideration: tx,
	}

	txJson, err := json.MarshalIndent(&t, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(txJson))
}

type history struct {
	Considerations []txWithContext `json:"considerations"`
}

func displayHistory(bIDs []PassID, indices []int, stopHeight int64, stopIndex int, passStore PassStorage) {
	h := history{Considerations: make([]txWithContext, len(indices))}
	for i := 0; i < len(indices); i++ {
		tx, header, err := passStore.GetConsideration(bIDs[i], indices[i])
		if err != nil {
			panic(err)
		}
		if tx == nil {
			panic("No consideration found at index")
		}
		txID, err := tx.ID()
		if err != nil {
			panic(err)
		}
		h.Considerations[i] = txWithContext{
			PassID:     bIDs[i],
			PassHeader: *header,
			TxIndex:     indices[i],
			ID:          txID,
			Consideration: tx,
		}
	}

	hJson, err := json.MarshalIndent(&h, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(hJson))
}

func verify(ledger Ledger, passStore PassStorage, pubKey ed25519.PublicKey, height int64) {
	var err error
	var expect, found int64

	if pubKey == nil {
		// compute expected total imbalance
		if height-PASSPOINT_MATURITY >= 0 {
			// sum all mature points per schedule
			var i int64
			for i = 0; i <= height-PASSPOINT_MATURITY; i++ {
				expect += 1
			}
		}

		// compute the imbalance given the sum of all public key imbalances
		found, err = ledger.Imbalance()
	} else {
		// get expected imbalance
		expect, err = ledger.GetPublicKeyImbalance(pubKey)
		if err != nil {
			log.Fatal(err)
		}

		// compute the imbalance based on history
		found, err = ledger.GetPublicKeyImbalanceAt(pubKey, height)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	if expect != found {
		log.Fatalf("%s: At height %d, we expected %+d crux but we found %+d\n",
			aurora.Bold(aurora.Red("FAILURE")),
			aurora.Bold(height),
			aurora.Bold(expect),
			aurora.Bold(found))
	}

	log.Printf("%s: At height %d, we expected %+d crux and we found %+d\n",
		aurora.Bold(aurora.Green("SUCCESS")),
		aurora.Bold(height),
		aurora.Bold(expect),
		aurora.Bold(found))
}
