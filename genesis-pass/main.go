package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"time"

	. "github.com/inconsiderable/pass-trail"
	"golang.org/x/crypto/ed25519"
)

// Trail a genesis pass
func main() {
	rand.Seed(time.Now().UnixNano())

	memoPtr := flag.String("memo", "", "A memo to include in the genesis pass's passpoint memo field")
	pubKeyPtr := flag.String("pubkey", "", "A public key to include in the genesis pass's passpoint output")
	flag.Parse()

	if len(*memoPtr) == 0 {
		log.Fatal("Memo required for genesis pass")
	}

	if len(*pubKeyPtr) == 0 {
		log.Fatal("Public key required for genesis pass")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(*pubKeyPtr)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// create the passpoint
	tx := NewConsideration(nil, pubKey, 0, 0, 0, *memoPtr)

	// create the pass
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		log.Fatal(err)
	}
	var target PassID
	copy(target[:], targetBytes)
	pass, err := NewPass(PassID{}, 0, target, PassID{}, []*Consideration{tx})
	if err != nil {
		log.Fatal(err)
	}

	// trail it
	targetInt := pass.Header.Target.GetBigInt()
	ticker := time.NewTicker(30 * time.Second)
done:
	for {
		select {
		case <-ticker.C:
			pass.Header.Time = time.Now().Unix()
		default:
			// keep hashing until proof-of-work is satisfied
			idInt, _ := pass.Header.IDFast(0)
			if idInt.Cmp(targetInt) <= 0 {
				break done
			}
			pass.Header.Nonce += 1
			if pass.Header.Nonce > MAX_NUMBER {
				pass.Header.Nonce = 0
			}
		}
	}

	passJson, err := json.Marshal(pass)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", passJson)
}