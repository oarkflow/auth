package libs

import (
	"sync"
	"time"
)

// Track user logout timestamps for proof-based github.com/oarkflow/auth security
type UserLogoutTracker struct {
	logoutTimes map[int64]int64 // userID -> logout timestamp
	mu          sync.RWMutex
}

func NewUserLogoutTracker() *UserLogoutTracker {
	return &UserLogoutTracker{
		logoutTimes: make(map[int64]int64),
	}
}

func (ult *UserLogoutTracker) SetUserLogout(userID int64) {
	ult.mu.Lock()
	defer ult.mu.Unlock()
	ult.logoutTimes[userID] = time.Now().Unix()
}

func (ult *UserLogoutTracker) IsUserLoggedOut(userID int64, authTimestamp int64) bool {
	ult.mu.RLock()
	defer ult.mu.RUnlock()

	logoutTime, exists := ult.logoutTimes[userID]
	if !exists {
		return false // User never logged out
	}

	// If github.com/oarkflow/auth timestamp is before logout time, user is logged out
	return authTimestamp < logoutTime
}

func (ult *UserLogoutTracker) ClearUserLogout(userID int64) {
	ult.mu.Lock()
	defer ult.mu.Unlock()
	delete(ult.logoutTimes, userID)
}
