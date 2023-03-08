package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lorenzosaino/go-sysctl"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Interface struct {
	name   string
	client *wgctrl.Client
	link   netlink.Link

	prevPeer map[wgtypes.Key]string
}

func New(name string, privateKey []byte, listenPort int) (_ *Interface, outErr error) {
	i := &Interface{
		name: name,
	}

	if link, err := netlink.LinkByName(name); err == nil {
		i.link = link
	} else {
		attr := netlink.NewLinkAttrs()
		attr.Name = name
		i.link = &netlink.GenericLink{
			LinkAttrs: attr,
			LinkType:  "wireguard",
		}

		// setup link
		if err := netlink.LinkAdd(i.link); err != nil {
			return nil, err
		}
		defer func() {
			if outErr != nil {
				netlink.LinkDel(i.link)
			}
		}()
	}

	// setup qdisc
	fq := &netlink.Fq{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: i.link.Attrs().Index,
			Parent:    netlink.HANDLE_ROOT,
		},
		Pacing: 1,
	}
	if err := netlink.QdiscReplace(fq); err != nil {
		return nil, err
	}

	// setup wg client
	if client, err := wgctrl.New(); err != nil {
		return nil, err
	} else {
		i.client = client
	}
	defer func() {
		if outErr != nil {
			i.client.Close()
		}
	}()

	// configure wg interface
	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		return nil, err
	}
	wgcfg := wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	}
	err = i.client.ConfigureDevice(name, wgcfg)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (i *Interface) AddrAdd(a string) error {
	ip, ipnet, err := net.ParseCIDR(a)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(i.link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := netlink.AddrDel(i.link, &addr); err != nil {
			return err
		}
	}
	err = netlink.AddrAdd(i.link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipnet.Mask,
		},
	})
	if err == nil || errors.Is(err, os.ErrExist) {
		return nil
	}
	return err
}

func (i *Interface) LinkUp() error {
	return netlink.LinkSetUp(i.link)
}

func (i *Interface) LinkIndex() int {
	return i.link.Attrs().Index
}

func (i *Interface) PeerSync(peers map[wgtypes.Key]string) error {
	if i.prevPeer == nil {
		dev, err := i.client.Device(i.name)
		if err != nil {
			return err
		}
		i.prevPeer = make(map[wgtypes.Key]string)
		for _, p := range dev.Peers {
			i.prevPeer[p.PublicKey] = p.AllowedIPs[0].IP.String()
		}
	}

	toDelete := make(map[wgtypes.Key]struct{})
	toAdd := make(map[wgtypes.Key]net.IP)
	for k, p := range i.prevPeer {
		if ip, ok := peers[k]; !ok {
			toDelete[k] = struct{}{}
		} else {
			if p != ip {
				toAdd[k] = net.ParseIP(ip)
			}
		}
	}
	for k := range peers {
		_, found := i.prevPeer[k]
		if !found {
			toAdd[k] = net.ParseIP(peers[k])
		}
	}

	wgcfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{},
	}
	for k := range toDelete {
		wgcfg.Peers = append(wgcfg.Peers, wgtypes.PeerConfig{
			PublicKey: k,
			Remove:    true,
		})
	}
	for k, ip := range toAdd {
		mask := net.CIDRMask(32, 32)
		wgcfg.Peers = append(wgcfg.Peers, wgtypes.PeerConfig{
			PublicKey: k,
			AllowedIPs: []net.IPNet{
				{
					IP:   ip,
					Mask: mask,
				},
			},
		})
	}

	i.prevPeer = peers
	return i.client.ConfigureDevice(i.name, wgcfg)
}

func (i *Interface) Close() error {
	return i.client.Close()
}

func (i *Interface) Delete() error {
	return netlink.LinkDel(i.link)
}

func (i *Interface) NatAdd(iface string) error {
	if val, err := sysctl.Get("net.ipv4.ip_forward"); err != nil {
		return err
	} else if val != "1" {
		if err := sysctl.Set("net.ipv4.ip_forward", "1"); err != nil {
			return err
		}
	}

	comment := fmt.Sprintf("wg-gatekeeper-%d", i.LinkIndex())

	tbl, err := iptables.New()
	if err != nil {
		return err
	}

	if err := clearChain(tbl, "filter", "FORWARD", comment); err != nil {
		return err
	}
	if err := clearChain(tbl, "nat", "POSTROUTING", comment); err != nil {
		return err
	}
	if err := clearChain(tbl, "mangle", "PREROUTING", comment); err != nil {
		return err
	}
	if iface == "" {
		return nil
	}

	mark := fmt.Sprintf("0x%x", 0x500+i.LinkIndex())
	err = tbl.AppendUnique("filter", "FORWARD", "-i", i.name, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
	if err != nil {
		return err
	}
	err = tbl.AppendUnique("filter", "FORWARD", "-o", i.name, "-i", iface, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
	if err != nil {
		return err
	}
	err = tbl.AppendUnique("mangle", "PREROUTING", "-i", i.name, "-j", "MARK", "--set-mark", mark, "-m", "comment", "--comment", comment)
	if err != nil {
		return err
	}
	err = tbl.AppendUnique("nat", "POSTROUTING", "-o", iface, "-m", "mark", "--mark", mark, "-j", "MASQUERADE", "-m", "comment", "--comment", comment)
	if err != nil {
		return err
	}
	return nil
}

func clearChain(ipt *iptables.IPTables, tbl, chain, comment string) error {
	rules, err := ipt.List(tbl, chain)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if strings.Contains(rule, comment) {
			if err := ipt.Delete(tbl, chain, strings.Split(strings.TrimPrefix(rule, "-A "+chain+" "), " ")...); err != nil {
				return err
			}
		}
	}
	return nil
}
