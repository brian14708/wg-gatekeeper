package wireguard

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Interface struct {
	name   string
	client *wgctrl.Client
	link   netlink.Link
}

func New(name string, privateKey string, listenPort int) (_ *Interface, outErr error) {
	i := &Interface{
		name: name,
	}

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
	key, err := wgtypes.ParseKey(privateKey)
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
	return netlink.AddrAdd(i.link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipnet.Mask,
		},
	})
}

func (i *Interface) LinkUp() error {
	return netlink.LinkSetUp(i.link)
}

func (i *Interface) LinkIndex() int {
	return i.link.Attrs().Index
}

func (i *Interface) PeerAdd(publicKey string, ip string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	addr := net.ParseIP(ip)
	mask := net.CIDRMask(32, 32)
	wgcfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: key,
				AllowedIPs: []net.IPNet{
					{
						IP:   addr,
						Mask: mask,
					},
				},
			},
		},
	}
	return i.client.ConfigureDevice(i.name, wgcfg)
}

func (i *Interface) PeerRemove(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	wgcfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: key,
				Remove:    true,
			},
		},
	}
	return i.client.ConfigureDevice(i.name, wgcfg)
}

func (i *Interface) Close() error {
	return errors.Join(
		netlink.LinkDel(i.link),
		i.client.Close(),
	)
}
