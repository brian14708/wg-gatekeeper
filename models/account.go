package models

import "gorm.io/gorm"

type Account struct {
	gorm.Model
	ID                int
	Name              string
	BandwidthInLimit  int64
	BandwidthOutLimit int64
	InterfaceID       int

	BytesIn  int64
	BytesOut int64

	Clients []Client
}
