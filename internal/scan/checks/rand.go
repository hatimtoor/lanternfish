package checks

import (
	"crypto/rand"
	"encoding/hex"
)

// randMarker returns prefix followed by an unpredictable hex token. Probe
// markers and canaries must be unguessable so a hostile target cannot detect
// and suppress them to evade scanning; crypto/rand provides that, math/rand
// does not.
func randMarker(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + "0a1b2c3d4e5f"
	}
	return prefix + hex.EncodeToString(b[:])
}
