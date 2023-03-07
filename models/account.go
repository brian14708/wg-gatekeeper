package models

import "gorm.io/gorm"

type Account struct {
	gorm.Model
	ID             int
	Name           string
	BandwidthLimit int64
	InterfaceID    int

	Clients []Client `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}
