package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/brian14708/wg-gatekeeper/bwfilter"
	"github.com/brian14708/wg-gatekeeper/models"
	"github.com/brian14708/wg-gatekeeper/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Syncer struct {
	updateInterface chan struct{}
	updateClients   chan struct{}
	updateAccounts  chan struct{}
	deleteInterface chan struct{}
}

func NewSyncer() *Syncer {
	s := &Syncer{
		updateInterface: make(chan struct{}, 1),
		updateClients:   make(chan struct{}, 1),
		updateAccounts:  make(chan struct{}, 1),
		deleteInterface: make(chan struct{}, 1),
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

func (s *Syncer) DeleteInterface() {
	select {
	case s.deleteInterface <- struct{}{}:
	default:
	}
}

const (
	AuditStep = time.Hour
)

func (s *Syncer) Run() {
	var wg *wireguard.Interface
	var handle *bwfilter.Handle
	ticker := time.NewTimer(30 * time.Second)
	for {
		select {
		case <-ticker.C:
			if handle == nil {
				ticker.Reset(30 * time.Second)
				continue
			}

			m := handle.Metrics()
			start := time.Now().Truncate(AuditStep)
			end := start.Add(AuditStep)
			for k, v := range m {
				if v.BytesIn < 4096 && v.BytesOut < 4096 {
					continue
				}
				dest := fmt.Sprintf("%s:%d", net.IP(binary.LittleEndian.AppendUint32(nil, k.DestIP)), k.DestPort)
				models.DB.Exec(
					`INSERT INTO audit_logs (client_id, destination, start_time, end_time, bytes_in, bytes_out) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (client_id, destination, start_time) DO UPDATE SET bytes_in = bytes_in + ?, bytes_out = bytes_out + ?`,
					k.ClientID, dest, start, end, v.BytesIn, v.BytesOut, v.BytesIn, v.BytesOut,
				)
			}
			ticker.Reset(30 * time.Second)

		case <-s.updateInterface:
			// update interface
			var iface models.Interface
			models.DB.First(&iface)
			if iface.ID == 0 {
				continue
			}
			i, err := wireguard.New(iface.Name, iface.PrivateKey, iface.ListenPort)
			if err != nil {
				panic(err)
			}
			err = i.AddrAdd(iface.Subnet)
			if err != nil {
				panic(err)
			}
			err = i.NatAdd(iface.NatIface, *flagEnovyTcp)
			if err != nil {
				panic(err)
			}
			err = i.LinkUp()
			if err != nil {
				panic(err)
			}
			old := handle
			handle, err = bwfilter.Attach(i.LinkIndex())
			if err != nil {
				log.Fatalf("attaching filter: %v", err)
			}
			if old != nil {
				old.Close()
			}
			wg = i
			s.UpdateAccounts()
			s.UpdateClients()

		case <-s.deleteInterface:
			if handle != nil {
				handle.Close()
				handle = nil
			}
			if wg != nil {
				wg.Delete()
				wg = nil
			}

		case <-s.updateClients:
			// update clients
			var iface models.Interface
			models.DB.First(&iface)

			rows, err := models.DB.Table("clients").
				Select("clients.public_key, clients.ip_address, accounts.id, clients.id, accounts.bandwidth_in_limit, accounts.bandwidth_out_limit").
				Joins("left join accounts on accounts.id = clients.account_id").
				Joins("left join interfaces on interfaces.id = accounts.interface_id").
				Where("interfaces.id = ?", iface.ID).
				Rows()
			if err != nil {
				panic(err)
			}
			peers := make(map[wgtypes.Key]string)
			accounts := make(map[string]bwfilter.ClientAccount)
			for rows.Next() {
				var pubKey string
				var ipAddr string
				var accountID int
				var clientID int
				var bandwidthInLimit int64
				var bandwidthOutLimit int64
				rows.Scan(&pubKey, &ipAddr, &accountID, &clientID, &bandwidthInLimit, &bandwidthOutLimit)
				k, err := wgtypes.NewKey([]byte(pubKey))
				if err != nil {
					panic(err)
				}
				peers[k] = ipAddr

				accounts[ipAddr] = bwfilter.ClientAccount{
					AccountID:    uint32(accountID),
					ClientID:     uint32(clientID),
					BandwidthIn:  uint64(bandwidthInLimit),
					BandwidthOut: uint64(bandwidthOutLimit),
				}
			}
			rows.Close()
			wg.PeerSync(peers)

			if err := handle.UpdateClientAccount(accounts); err != nil {
				log.Fatalf("updating client account: %v", err)
			}

		case <-s.updateAccounts:
			s.UpdateClients()
		}
	}
}
