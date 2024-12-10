package passtrail

import (
	"bytes"
	"container/list"
	"encoding/base64"
	"fmt"
	"sync"
)

// ConsiderationQueueMemory is an in-memory FIFO implementation of the ConsiderationQueue interface.
type ConsiderationQueueMemory struct {
	txMap        	map[ConsiderationID]*list.Element
	txQueue      	*list.List
	imbalanceCache 	*ImbalanceCache
	conGraph      	*Graph
	lock         	sync.RWMutex
}

// NewConsiderationQueueMemory returns a new NewConsiderationQueueMemory instance.
func NewConsiderationQueueMemory(ledger Ledger, conGraph *Graph) *ConsiderationQueueMemory {

	return &ConsiderationQueueMemory{
		txMap:        	make(map[ConsiderationID]*list.Element),
		txQueue:      	list.New(),
		imbalanceCache:	NewImbalanceCache(ledger),
		conGraph: 		conGraph,
	}
}

// Add adds the consideration to the queue. Returns true if the consideration was added to the queue on this call.
func (t *ConsiderationQueueMemory) Add(id ConsiderationID, tx *Consideration) (bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if _, ok := t.txMap[id]; ok {
		// already exists
		return false, nil
	}

	// check sender imbalance and update sender and receiver imbalances
	ok, err := t.imbalanceCache.Apply(tx)
	if err != nil {
		return false, err
	}
	if !ok {
		// insufficient sender imbalance
		return false, fmt.Errorf("Consideration %s benefactor %s has insufficient imbalance",
			id, base64.StdEncoding.EncodeToString(tx.By[:]))
	}

	if t.conGraph.IsParentDescendant(pubKeyToString(tx.For), pubKeyToString(tx.By)){
		return false, fmt.Errorf("Benefactor is a descendant of beneficiary in consideration %s", id)
	}

	// add to the back of the queue
	e := t.txQueue.PushBack(tx)
	t.txMap[id] = e
	return true, nil
}

// AddBatch adds a batch of considerations to the queue (a pass has been disconnected.)
// "height" is the pass trail height after this disconnection.
func (t *ConsiderationQueueMemory) AddBatch(ids []ConsiderationID, txs []*Consideration, height int64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// add to front in reverse order.
	// we want formerly confirmed considerations to have the highest
	// priority for getting into the next pass.
	for i := len(txs) - 1; i >= 0; i-- {
		if e, ok := t.txMap[ids[i]]; ok {
			// remove it from its current position
			t.txQueue.Remove(e)
		}
		e := t.txQueue.PushFront(txs[i])
		t.txMap[ids[i]] = e
	}

	// we don't want to invalidate anything based on maturity/expiration/imbalance yet.
	// if we're disconnecting a pass we're going to be connecting some shortly.
	return nil
}

// RemoveBatch removes a batch of considerations from the queue (a pass has been connected.)
// "height" is the pass trail height after this connection.
// "more" indicates if more connections are coming.
func (t *ConsiderationQueueMemory) RemoveBatch(ids []ConsiderationID, height int64, more bool) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	for _, id := range ids {
		e, ok := t.txMap[id]
		if !ok {
			// not in the queue
			continue
		}
		// remove it
		t.txQueue.Remove(e)
		delete(t.txMap, id)
	}

	if more {
		// we don't want to invalidate anything based on series/maturity/expiration/imbalance
		// until we're done connecting all of the passes we intend to
		return nil
	}

	return t.reprocessQueue(height)
}

// Rebuild the imbalance cache and remove considerations now in violation
func (t *ConsiderationQueueMemory) reprocessQueue(height int64) error {
	// invalidate the cache
	t.imbalanceCache.Reset()

	// remove invalidated considerations from the queue
	tmpQueue := list.New()
	tmpQueue.PushBackList(t.txQueue)
	for e := tmpQueue.Front(); e != nil; e = e.Next() {
		tx := e.Value.(*Consideration)
		// check that the series would still be valid
		if !checkConsiderationSeries(tx, height+1) ||
			// check maturity and expiration if included in the next pass
			!tx.IsMature(height+1) || tx.IsExpired(height+1) {
			// consideration has been invalidated. remove and continue
			id, err := tx.ID()
			if err != nil {
				return err
			}
			e := t.txMap[id]
			t.txQueue.Remove(e)
			delete(t.txMap, id)
			continue
		}

		// check imbalance
		ok, err := t.imbalanceCache.Apply(tx)
		if err != nil {
			return err
		}
		if !ok || t.conGraph.IsParentDescendant(pubKeyToString(tx.For), pubKeyToString(tx.By)) {
			// consideration has been invalidated. remove and continue
			id, err := tx.ID()
			if err != nil {
				return err
			}
			e := t.txMap[id]
			t.txQueue.Remove(e)
			delete(t.txMap, id)
			continue
		}
	}
	return nil
}

// Get returns considerations in the queue for the trailer.
func (t *ConsiderationQueueMemory) Get(limit int) []*Consideration {
	var txs []*Consideration
	t.lock.RLock()
	defer t.lock.RUnlock()
	if limit == 0 || t.txQueue.Len() < limit {
		txs = make([]*Consideration, t.txQueue.Len())
	} else {
		txs = make([]*Consideration, limit)
	}
	i := 0
	for e := t.txQueue.Front(); e != nil; e = e.Next() {
		txs[i] = e.Value.(*Consideration)
		i++
		if i == limit {
			break
		}
	}
	return txs
}

// Exists returns true if the given consideration is in the queue.
func (t *ConsiderationQueueMemory) Exists(id ConsiderationID) bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	_, ok := t.txMap[id]
	return ok
}

// ExistsSigned returns true if the given consideration is in the queue and contains the given signature.
func (t *ConsiderationQueueMemory) ExistsSigned(id ConsiderationID, signature Signature) bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	if e, ok := t.txMap[id]; ok {
		tx := e.Value.(*Consideration)
		return bytes.Equal(tx.Signature, signature)
	}
	return false
}

// Len returns the queue length.
func (t *ConsiderationQueueMemory) Len() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.txQueue.Len()
}
