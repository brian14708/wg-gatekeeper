package models

import (
	"time"

	"gorm.io/gorm"
)

type AuditLog struct {
	gorm.Model
	ID          int
	ClientID    int       `gorm:"index:log_idx"`
	Destination string    `gorm:"index:log_idx"`
	StartTime   time.Time `gorm:"index:log_idx"`
	EndTime     time.Time
	BytesIn     int64
	BytesOut    int64
}
