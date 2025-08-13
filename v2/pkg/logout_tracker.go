package pkg

import (
	"sync"
	"time"
)

// Track user logout timestamps for proof-based github.com/oarkflow/auth security
type UserLogoutTracker struct {
	logoutTimes map[string]int64 // userID -> logout timestamp
	mu          sync.RWMutex
}

func NewUserLogoutTracker() *UserLogoutTracker {
	return &UserLogoutTracker{
		logoutTimes: make(map[string]int64),
	}
}

func (ult *UserLogoutTracker) SetUserLogout(userID string) {
	ult.mu.Lock()
	defer ult.mu.Unlock()
	ult.logoutTimes[userID] = time.Now().Unix()
}

func (ult *UserLogoutTracker) IsUserLoggedOut(userID string, authTimestamp int64) bool {
	ult.mu.RLock()
	defer ult.mu.RUnlock()

	logoutTime, exists := ult.logoutTimes[userID]
	if !exists {
		return false // User never logged out
	}

	// If github.com/oarkflow/auth timestamp is before logout time, user is logged out
	return authTimestamp < logoutTime
}

func (ult *UserLogoutTracker) ClearUserLogout(userID string) {
	ult.mu.Lock()
	defer ult.mu.Unlock()
	delete(ult.logoutTimes, userID)
}
