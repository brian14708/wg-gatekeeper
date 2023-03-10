package models

import (
	"gorm.io/gorm"
)

type Interface struct {
	gorm.Model
	ID         int
	Name       string
	PrivateKey []byte
	ListenPort int
	NatIface   string
	Subnet     string
	ExternalIP string
	DNS        string

	Accounts []Account
}
