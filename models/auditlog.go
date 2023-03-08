package models

import (
	"time"

	"gorm.io/gorm"
)

type AuditLog struct {
	gorm.Model
	ID          int
	ClientID    int       `gorm:"index:log_idx,unique"`
	Destination string    `gorm:"index:log_idx,unique"`
	StartTime   time.Time `gorm:"index:log_idx,unique"`
	EndTime     time.Time
	BytesIn     int64
	BytesOut    int64
}
