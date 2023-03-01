package models

import (
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Interface struct {
	gorm.Model
	ID     int
	Config datatypes.JSONType[struct {
		Name       string
		PrivateKey []byte
		ListenPort int
		NatForward string
	}]
}
