package models

import "gorm.io/gorm"

type Client struct {
	gorm.Model
	ID        int
	Name      string
	PublicKey []byte
	IPAddress string `gorm:"uniqueIndex"`

	AccountID int
	AuditLogs []AuditLog `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}
