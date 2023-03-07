package main

import (
	"github.com/brian14708/wg-gatekeeper/models"
	"github.com/brian14708/wg-gatekeeper/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Syncer struct {
	updateInterface chan struct{}
	updateClients   chan struct{}
	updateAccounts  chan struct{}
}

func NewSyncer() *Syncer {
	s := &Syncer{
		updateInterface: make(chan struct{}, 1),
		updateClients:   make(chan struct{}, 1),
		updateAccounts:  make(chan struct{}, 1),
	}
	go s.Run()
	return s
}

func (s *Syncer) UpdateInterface() {
	select {
	case s.updateInterface <- struct{}{}:
	default:
	}
}

func (s *Syncer) UpdateClients() {
	select {
	case s.updateClients <- struct{}{}:
	default:
	}
}

func (s *Syncer) UpdateAccounts() {
	select {
	case s.updateAccounts <- struct{}{}:
	default:
	}
}

func (s *Syncer) Run() {
	var wg *wireguard.Interface
	for {
		select {
		case <-s.updateInterface:
			// update interface
			var iface models.Interface
			models.DB.First(&iface)
			i, err := wireguard.New(iface.Name, iface.PrivateKey, iface.ListenPort)
			if err != nil {
				panic(err)
			}
			err = i.AddrAdd(iface.Subnet)
			if err != nil {
				panic(err)
			}
			err = i.NatAdd(iface.NatIface)
			if err != nil {
				panic(err)
			}
			err = i.LinkUp()
			if err != nil {
				panic(err)
			}
			wg = i
			s.UpdateAccounts()
			s.UpdateClients()
		case <-s.updateClients:
			// update clients
			var iface models.Interface
			models.DB.First(&iface)

			rows, err := models.DB.Table("clients").
				Select("clients.public_key, clients.ip_address").
				Joins("left join accounts on accounts.id = clients.account_id").
				Joins("left join interfaces on interfaces.id = accounts.interface_id").
				Where("interfaces.id = ?", iface.ID).
				Rows()
			if err != nil {
				panic(err)
			}
			peers := make(map[wgtypes.Key]string)
			for rows.Next() {
				var pubKey string
				var ipAddr string
				rows.Scan(&pubKey, &ipAddr)
				k, err := wgtypes.NewKey([]byte(pubKey))
				if err != nil {
					panic(err)
				}
				peers[k] = ipAddr
			}
			rows.Close()
			wg.PeerSync(peers)

		case <-s.updateAccounts:
			// update accounts
			var iface models.Interface
			models.DB.Preload("Accounts").First(&iface)
			// TODO
			s.UpdateClients()
		}
	}
}
