package models

import "gorm.io/gorm"

type Account struct {
	gorm.Model
	ID                int
	Name              string
	BandwidthInLimit  int64
	BandwidthOutLimit int64
	InterfaceID       int

	Clients []Client
}
