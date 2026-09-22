package models

import "time"

type User struct {
	ID             int64     `gorm:"primaryKey"`
	Username       string    `gorm:"uniqueIndex;size:32;not null"`
	PasswordHash   string    `gorm:"not null"`
	RegisteredAt   time.Time `gorm:"autoCreateTime"`
	LastLoginAt    *time.Time
	MFAEnabled     bool `gorm:"not null;default:false"`
	TOTPSecret     *string
	FailedAttempts int `gorm:"not null; default:0"`
	LockedUntil    *time.Time
}
