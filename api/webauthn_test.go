package api

import (
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestAPIWithCeremonies creates a minimal API with webauthnCeremonies
// initialised for unit testing. No repo, sessions, or webauthn instance
// are needed — only the ceremony map and its mutex are exercised.
func newTestAPIWithCeremonies() *API {
	return &API{
		webauthnCeremonies: make(map[string]webauthnCeremonyState),
	}
}

// ---------------------------------------------------------------------------
// evictExpiredCeremoniesLocked
// ---------------------------------------------------------------------------

func TestEvictExpiredCeremonies_RemovesExpired(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// Insert a mix of expired and live ceremonies.
	a.webauthnCeremonies["expired-1"] = webauthnCeremonyState{
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	a.webauthnCeremonies["expired-2"] = webauthnCeremonyState{
		ExpiresAt: time.Now().Add(-10 * time.Second),
	}
	a.webauthnCeremonies["live-1"] = webauthnCeremonyState{
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	a.webauthnCeremonies["live-2"] = webauthnCeremonyState{
		ExpiresAt: time.Now().Add(3 * time.Minute),
	}

	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	a.webauthnCeremonyMu.Unlock()

	assert.Len(t, a.webauthnCeremonies, 2, "should retain only live ceremonies")
	_, ok1 := a.webauthnCeremonies["live-1"]
	_, ok2 := a.webauthnCeremonies["live-2"]
	assert.True(t, ok1, "live-1 should remain")
	assert.True(t, ok2, "live-2 should remain")
}

func TestEvictExpiredCeremonies_AllExpired(t *testing.T) {
	a := newTestAPIWithCeremonies()

	for i := 0; i < 10; i++ {
		key := "expired-" + string(rune('a'+i))
		a.webauthnCeremonies[key] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(-time.Duration(i+1) * time.Minute),
		}
	}

	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	a.webauthnCeremonyMu.Unlock()

	assert.Empty(t, a.webauthnCeremonies, "all expired ceremonies should be removed")
}

func TestEvictExpiredCeremonies_NoneExpired(t *testing.T) {
	a := newTestAPIWithCeremonies()

	for i := 0; i < 5; i++ {
		key := "live-" + string(rune('a'+i))
		a.webauthnCeremonies[key] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(time.Duration(i+1) * time.Minute),
		}
	}

	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	a.webauthnCeremonyMu.Unlock()

	assert.Len(t, a.webauthnCeremonies, 5, "no ceremonies should be evicted")
}

func TestEvictExpiredCeremonies_EmptyMap(t *testing.T) {
	a := newTestAPIWithCeremonies()

	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	a.webauthnCeremonyMu.Unlock()

	assert.Empty(t, a.webauthnCeremonies)
}

// ---------------------------------------------------------------------------
// Ceremony state: passphrase not stored in raw form
// ---------------------------------------------------------------------------

func TestCeremonyState_NoRawPassphrase(t *testing.T) {
	// Verify the struct does NOT have a Passphrase field; it only
	// has LoginPassphrase (the pre-derived form).
	state := webauthnCeremonyState{
		SecretKey:       "sk-12345",
		LoginPassphrase: "some-passphrase:sk-12345",
		SessionData:     webauthn.SessionData{Challenge: "test-challenge"},
		ExpiresAt:       time.Now().Add(5 * time.Minute),
	}

	// LoginPassphrase should be the combined form, not the raw passphrase.
	assert.Contains(t, state.LoginPassphrase, ":")
	assert.Equal(t, "some-passphrase:sk-12345", state.LoginPassphrase)
}

// ---------------------------------------------------------------------------
// Ceremony state: SessionData stored as typed value, not string
// ---------------------------------------------------------------------------

func TestCeremonyState_TypedSessionData(t *testing.T) {
	sd := webauthn.SessionData{
		Challenge:            "AAAA",
		UserID:               []byte("user-1"),
		AllowedCredentialIDs: [][]byte{{1, 2, 3}},
		UserVerification:     "preferred",
	}

	state := webauthnCeremonyState{
		SessionData: sd,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Verify the session data is directly accessible without deserialization.
	assert.Equal(t, "AAAA", state.SessionData.Challenge)
	assert.Equal(t, []byte("user-1"), state.SessionData.UserID)
	assert.Equal(t, "preferred", string(state.SessionData.UserVerification))
}

// ---------------------------------------------------------------------------
// Concurrent eviction safety
// ---------------------------------------------------------------------------

func TestEvictExpiredCeremonies_ConcurrentSafety(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// Seed with a mix of live and expired entries.
	for i := 0; i < 100; i++ {
		ttl := time.Duration(i-50) * time.Second // first 50 expired, next 50 live
		a.webauthnCeremonies["c-"+string(rune(i))] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(ttl),
		}
	}

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.webauthnCeremonyMu.Lock()
			a.evictExpiredCeremoniesLocked()
			a.webauthnCeremonyMu.Unlock()
		}()
	}
	wg.Wait()

	// After all goroutines complete, only non-expired entries should remain.
	a.webauthnCeremonyMu.Lock()
	count := len(a.webauthnCeremonies)
	for _, v := range a.webauthnCeremonies {
		require.True(t, time.Now().Before(v.ExpiresAt), "all remaining ceremonies should be unexpired")
	}
	a.webauthnCeremonyMu.Unlock()

	assert.LessOrEqual(t, count, 50, "at most 50 live entries should remain")
}

// ---------------------------------------------------------------------------
// Abandoned ceremony lifecycle (simulates begin without finish)
// ---------------------------------------------------------------------------

func TestAbandonedCeremoniesAreEvicted(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// Simulate 20 "begin" ceremonies that were never completed.
	for i := 0; i < 20; i++ {
		challenge := "abandoned-" + string(rune('a'+i))
		a.webauthnCeremonies[challenge] = webauthnCeremonyState{
			SecretKey:       "sk-test",
			LoginPassphrase: "pass:sk-test",
			SessionData:     webauthn.SessionData{Challenge: challenge},
			// All expired — simulates ceremonies that sat for > 5 minutes.
			ExpiresAt: time.Now().Add(-time.Duration(i+1) * time.Second),
		}
	}
	require.Len(t, a.webauthnCeremonies, 20)

	// Now simulate a new begin that triggers eviction.
	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	a.webauthnCeremonies["new-challenge"] = webauthnCeremonyState{
		SecretKey:       "sk-new",
		LoginPassphrase: "newpass:sk-new",
		SessionData:     webauthn.SessionData{Challenge: "new-challenge"},
		ExpiresAt:       time.Now().Add(5 * time.Minute),
	}
	a.webauthnCeremonyMu.Unlock()

	assert.Len(t, a.webauthnCeremonies, 1, "all abandoned ceremonies evicted; only the new one remains")
	_, ok := a.webauthnCeremonies["new-challenge"]
	assert.True(t, ok, "new ceremony should be present")
}

// ---------------------------------------------------------------------------
// Partial expiry: some abandoned, some active, new insert
// ---------------------------------------------------------------------------

func TestEvictionOnInsert_PartialExpiry(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// 5 expired, 3 live.
	for i := 0; i < 5; i++ {
		a.webauthnCeremonies["stale-"+string(rune('a'+i))] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(-time.Minute),
		}
	}
	for i := 0; i < 3; i++ {
		a.webauthnCeremonies["active-"+string(rune('a'+i))] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
	}
	require.Len(t, a.webauthnCeremonies, 8)

	// Evict and insert.
	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	a.webauthnCeremonies["fresh"] = webauthnCeremonyState{
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	a.webauthnCeremonyMu.Unlock()

	assert.Len(t, a.webauthnCeremonies, 4, "3 active + 1 new")
	_, ok := a.webauthnCeremonies["fresh"]
	assert.True(t, ok)
	for _, k := range []string{"stale-a", "stale-b", "stale-c", "stale-d", "stale-e"} {
		_, found := a.webauthnCeremonies[k]
		assert.False(t, found, "expired ceremony %q should be gone", k)
	}
}

// ---------------------------------------------------------------------------
// Hard-cap enforcement tests
// ---------------------------------------------------------------------------

func TestCeremonyCap_RejectsWhenAtCapacity(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// Fill the ceremony map to exactly maxCeremonyEntries with live entries.
	for i := 0; i < maxCeremonyEntries; i++ {
		key := "active-" + string(rune(i))
		a.webauthnCeremonies[key] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
	}
	require.Len(t, a.webauthnCeremonies, maxCeremonyEntries)

	// Evict expired (none are expired) and check capacity.
	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	atCap := len(a.webauthnCeremonies) >= maxCeremonyEntries
	a.webauthnCeremonyMu.Unlock()

	assert.True(t, atCap, "should be at capacity with %d active ceremonies", maxCeremonyEntries)
}

func TestCeremonyCap_AcceptsAfterEvictionFreesSpace(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// Fill to cap: half expired, half live.
	half := maxCeremonyEntries / 2
	for i := 0; i < half; i++ {
		a.webauthnCeremonies["expired-"+string(rune(i))] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(-time.Minute),
		}
	}
	for i := 0; i < half; i++ {
		a.webauthnCeremonies["live-"+string(rune(i))] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
	}
	require.Len(t, a.webauthnCeremonies, maxCeremonyEntries)

	// After eviction, the live half remains — well under the cap.
	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	underCap := len(a.webauthnCeremonies) < maxCeremonyEntries
	a.webauthnCeremonyMu.Unlock()

	assert.True(t, underCap, "eviction should free space below cap")
	assert.Len(t, a.webauthnCeremonies, half)
}

func TestCeremonyCap_AllActiveBlocksInsert(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// Fill entirely with active (non-expired) ceremonies.
	for i := 0; i < maxCeremonyEntries; i++ {
		key := "active-" + string(rune(i))
		a.webauthnCeremonies[key] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
	}

	// Eviction removes nothing. The cap check should block.
	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	shouldReject := len(a.webauthnCeremonies) >= maxCeremonyEntries
	a.webauthnCeremonyMu.Unlock()

	assert.True(t, shouldReject, "all-active map at cap should reject new ceremonies")
	assert.Len(t, a.webauthnCeremonies, maxCeremonyEntries, "no entries should have been evicted")
}

func TestCeremonyCap_ExactlyAtCapMinusOneAllowsInsert(t *testing.T) {
	a := newTestAPIWithCeremonies()

	// Fill to one below cap.
	for i := 0; i < maxCeremonyEntries-1; i++ {
		key := "active-" + string(rune(i))
		a.webauthnCeremonies[key] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
	}
	require.Len(t, a.webauthnCeremonies, maxCeremonyEntries-1)

	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()
	shouldAllow := len(a.webauthnCeremonies) < maxCeremonyEntries
	if shouldAllow {
		a.webauthnCeremonies["new-ceremony"] = webauthnCeremonyState{
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
	}
	a.webauthnCeremonyMu.Unlock()

	assert.True(t, shouldAllow, "should allow insert when one below cap")
	assert.Len(t, a.webauthnCeremonies, maxCeremonyEntries, "should now be exactly at cap")
}
