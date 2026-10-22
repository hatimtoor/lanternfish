package session

import (
	"sync"
	"time"
)

// WSMessage is one observed WebSocket frame.
type WSMessage struct {
	ID        int64     `json:"id"`
	URL       string    `json:"url"`
	Direction string    `json:"direction"` // "c2s" (client->server) or "s2c"
	Opcode    int       `json:"opcode"`    // 1 text, 2 binary
	Text      string    `json:"text"`
	Length    int       `json:"length"`
	Time      time.Time `json:"time"`
}

// WSLog stores observed WebSocket traffic.
type WSLog struct {
	mu     sync.RWMutex
	nextID int64
	msgs   []WSMessage
}

// maxWSMessages bounds retained WebSocket messages to cap memory.
const maxWSMessages = 100000

func newWSLog() *WSLog { return &WSLog{} }

// Add records a WebSocket message and returns its id.
func (l *WSLog) Add(url, direction string, opcode int, payload []byte) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	text := ""
	if opcode == 1 { // text frame
		text = string(payload)
	}
	l.msgs = append(l.msgs, WSMessage{
		ID: l.nextID, URL: url, Direction: direction, Opcode: opcode,
		Text: text, Length: len(payload), Time: time.Now(),
	})
	if len(l.msgs) > maxWSMessages {
		l.msgs = append([]WSMessage(nil), l.msgs[len(l.msgs)-maxWSMessages:]...)
	}
	return l.nextID
}

// Messages returns up to limit most-recent messages (0 = all), newest first.
func (l *WSLog) Messages(limit int) []WSMessage {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := len(l.msgs)
	out := make([]WSMessage, n)
	for i := range l.msgs {
		out[n-1-i] = l.msgs[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Count returns the number of recorded WebSocket messages.
func (l *WSLog) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.msgs)
}
