package passtrail

import (
	"container/list"
	"sync"
	"time"
)

// PassQueue is a queue of passes to download.
type PassQueue struct {
	passMap   map[PassID]*list.Element
	passQueue *list.List
	lock       sync.RWMutex
}

// If a pass has been in the queue for more than 2 minutes it can be re-added with a new peer responsible for its download.
const maxQueueWait = 2 * time.Minute

type passQueueEntry struct {
	id   PassID
	who  string
	when time.Time
}

// NewPassQueue returns a new instance of a PassQueue.
func NewPassQueue() *PassQueue {
	return &PassQueue{
		passMap:   make(map[PassID]*list.Element),
		passQueue: list.New(),
	}
}

// Add adds the pass ID to the back of the queue and records the address of the peer who pushed it if it didn't exist in the queue.
// If it did exist and maxQueueWait has elapsed, the pass is left in its position but the peer responsible for download is updated.
func (b *PassQueue) Add(id PassID, who string) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if e, ok := b.passMap[id]; ok {
		entry := e.Value.(*passQueueEntry)
		if time.Since(entry.when) < maxQueueWait {
			// it's still pending download
			return false
		}
		// it's expired. signal that it can be tried again and leave it in place
		entry.when = time.Now()
		// new peer owns its place in the queue
		entry.who = who
		return true
	}

	// add to the back of the queue
	entry := &passQueueEntry{id: id, who: who, when: time.Now()}
	e := b.passQueue.PushBack(entry)
	b.passMap[id] = e
	return true
}

// Remove removes the pass ID from the queue only if the requester is who is currently responsible for its download.
func (b *PassQueue) Remove(id PassID, who string) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if e, ok := b.passMap[id]; ok {
		entry := e.Value.(*passQueueEntry)
		if entry.who == who {
			b.passQueue.Remove(e)
			delete(b.passMap, entry.id)
			return true
		}
	}
	return false
}

// Exists returns true if the pass ID exists in the queue.
func (b *PassQueue) Exists(id PassID) bool {
	b.lock.RLock()
	defer b.lock.RUnlock()
	_, ok := b.passMap[id]
	return ok
}

// Peek returns the ID of the pass at the front of the queue.
func (b *PassQueue) Peek() (PassID, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	if b.passQueue.Len() == 0 {
		return PassID{}, false
	}
	e := b.passQueue.Front()
	entry := e.Value.(*passQueueEntry)
	return entry.id, true
}

// Len returns the length of the queue.
func (b *PassQueue) Len() int {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.passQueue.Len()
}
