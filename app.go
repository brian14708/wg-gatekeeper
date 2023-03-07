package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/brian14708/wg-gatekeeper/models"

	"github.com/gofiber/fiber/v2"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/netaddr.v1"
	"gorm.io/gorm"
)

func appHandler(app *fiber.App) {
	// all accounts
	app.Get("/", func(c *fiber.Ctx) error {
		type Account struct {
			ID      int
			Name    string
			Clients int
		}
		var result []Account
		rows, err := models.DB.Table("accounts").
			Select("accounts.id, accounts.name, count(clients.id)").
			Where("accounts.deleted_at is null").
			Joins("left join clients on clients.account_id = accounts.id").
			Group("clients.account_id").
			Rows()
		if err != nil {
			return c.SendStatus(500)
		}
		defer rows.Close()
		for rows.Next() {
			var r Account
			if err := rows.Scan(&r.ID, &r.Name, &r.Clients); err != nil {
				return c.SendStatus(500)
			}
			result = append(result, r)
		}

		return c.Render("all_account", fiber.Map{
			"Accounts": result,
		})
	})

	// get account
	app.Get("/account/:id", func(c *fiber.Ctx) error {
		var acc models.Account
		models.DB.Preload("Clients", func(db *gorm.DB) *gorm.DB {
			return db.Order("clients.id DESC")
		}).First(&acc, c.Params("id"))
		return c.Render("account", fiber.Map{
			"Account": acc,
		})
	})

	// create account
	app.Post("/account", func(c *fiber.Ctx) error {
		var iface models.Interface
		models.DB.First(&iface)

		var acc models.Account
		acc.Name = c.FormValue("name")
		acc.InterfaceID = iface.ID

		if bw, err := strconv.ParseFloat(c.FormValue("bandwidth_limit"), 64); err != nil {
			flashError(c, "Invalid bandwidth limit")
			return c.Redirect("/")
		} else {
			acc.BandwidthLimit = int64(bw * 1024 * 1024)
		}
		ret := models.DB.Create(&acc)
		if ret.Error != nil {
			flashError(c, ret.Error.Error())
		}
		return c.Redirect("/")
	})

	// update account
	app.Post("/account/:id", func(c *fiber.Ctx) error {
		var acc models.Account
		models.DB.First(&acc, c.Params("id"))

		if bw, err := strconv.ParseFloat(c.FormValue("bandwidth_limit"), 64); err != nil {
			flashError(c, "Invalid bandwidth limit")
			return c.Redirect("/")
		} else {
			acc.BandwidthLimit = int64(bw * 1024 * 1024)
		}
		ret := models.DB.Save(&acc)
		if ret.Error != nil {
			flashError(c, ret.Error.Error())
		} else {
			flashInfo(c, "Account updated")
		}
		syncer.UpdateAccounts()
		return c.Redirect("/account/" + c.Params("id"))
	})

	// delete account
	app.Get("/account/:id/delete", func(c *fiber.Ctx) error {
		ret := models.DB.Unscoped().Delete(&models.Account{}, c.Params("id"))
		if ret.Error != nil {
			flashError(c, ret.Error.Error())
		} else {
			flashInfo(c, "Account deleted")
		}
		syncer.UpdateAccounts()
		return c.Redirect("/")
	})

	// create client
	app.Post("/account/:id/client", func(c *fiber.Ctx) error {
		var cli models.Client
		cli.AccountID, _ = strconv.Atoi(c.Params("id"))
		cli.Name = c.FormValue("name")

		key, err := wgtypes.GenerateKey()
		if err != nil {
			flashError(c, err.Error())
			return c.Redirect("/account/" + c.Params("id"))
		}
		pub := key.PublicKey()
		cli.PublicKey = pub[:]

		iface := models.Interface{}
		models.DB.First(&iface)

		var newestClient models.Client
		models.DB.Last(&newestClient)

		{
			ip, cidr, err := net.ParseCIDR(iface.Subnet)
			if err != nil {
				panic(err)
			}
			if newestClient.IPAddress != "" {
				ip = net.ParseIP(newestClient.IPAddress)
			}
			ip, err = nextIP(ip, cidr)
			if err != nil {
				panic(err)
			}
			cli.IPAddress = ip.String()
		}

		var ips netaddr.IPSet
		ips.InsertNet(mustCIDR("0.0.0.0/0"))
		ips.RemoveNet(mustCIDR("10.0.0.0/8"))
		ips.RemoveNet(mustCIDR("127.0.0.0/8"))
		ips.RemoveNet(mustCIDR("172.16.0.0/12"))
		ips.RemoveNet(mustCIDR("192.168.0.0/16"))
		ips.RemoveNet(mustCIDR("224.0.0.0/4"))
		ips.RemoveNet(mustCIDR(iface.ExternalIP + "/32"))
		cidrStr := strings.Join(ips.String(), ",")

		config := fmt.Sprintf(`[Interface]
Address = %s
PrivateKey = %s
[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = %s`,
			cli.IPAddress,
			key.String(),
			wgtypes.Key(iface.PrivateKey).PublicKey().String(),
			iface.ExternalIP,
			iface.ListenPort,
			cidrStr,
		)
		ret := models.DB.Create(&cli)
		if ret.Error != nil {
			flashError(c, ret.Error.Error())
			return c.Redirect("/account/" + c.Params("id"))
		}
		syncer.UpdateClients()
		return c.Render("client", fiber.Map{
			"Client":    cli,
			"AccountID": c.Params("id"),
			"Config":    config,
		})
	})

	// delete client
	app.Get("/account/:id/client/:cid/delete", func(c *fiber.Ctx) error {
		var cli models.Client
		models.DB.Unscoped().Delete(&cli, c.Params("cid"))
		syncer.UpdateClients()
		return c.Redirect("/account/" + c.Params("id"))
	})

	// get settings
	app.Get("/interface", func(c *fiber.Ctx) error {
		iface := models.Interface{}
		models.DB.First(&iface)

		links, _ := netlink.LinkList()
		var attrs []*netlink.LinkAttrs
		var ip string
		for _, l := range links {
			a := l.Attrs()
			if a.Name == iface.Name || a.OperState == netlink.OperDown || a.Flags&net.FlagLoopback != 0 {
				continue
			}
			attrs = append(attrs, a)
			if ip == "" {
				addrs, _ := netlink.AddrList(l, netlink.FAMILY_V4)
				for _, addr := range addrs {
					ip = addr.IP.String()
					break
				}
			}
		}

		return c.Render("interface", fiber.Map{
			"Iface":   iface,
			"Links":   attrs,
			"GuessIP": ip,
		})
	})

	// update settings
	app.Post("/interface", func(c *fiber.Ctx) error {
		iface := models.Interface{}
		models.DB.First(&iface)

		iface.Name = c.FormValue("name")
		if len(iface.PrivateKey) == 0 {
			key, err := wgtypes.GenerateKey()
			if err != nil {
				flashError(c, "Failed to generate private key")
				return c.Redirect("/interface")
			}
			iface.PrivateKey = key[:]
		}
		if p, err := strconv.Atoi(c.FormValue("listen_port")); err != nil {
			flashError(c, "Invalid listen port")
			return c.Redirect("/interface")
		} else {
			iface.ListenPort = p
		}
		if _, _, err := net.ParseCIDR(c.FormValue("subnet")); err != nil {
			flashError(c, "Invalid subnet")
			return c.Redirect("/interface")
		}
		iface.Subnet = c.FormValue("subnet")
		iface.NatIface = c.FormValue("nat_iface")
		iface.ExternalIP = c.FormValue("external_ip")

		ret := models.DB.Save(&iface)
		if ret.Error != nil {
			flashError(c, ret.Error.Error())
			return c.Redirect("/interface")
		} else {
			flashInfo(c, "Interface updated")
			syncer.UpdateInterface()
			return c.Redirect("/")
		}
	})
}

func flashError(c *fiber.Ctx, msg string) {
	c.Cookie(&fiber.Cookie{
		Name:        "flash_error",
		Value:       msg,
		Expires:     time.Now().Add(24 * time.Hour),
		HTTPOnly:    true,
		SessionOnly: true,
	})
}

func flashInfo(c *fiber.Ctx, msg string) {
	c.Cookie(&fiber.Cookie{
		Name:        "flash_info",
		Value:       msg,
		Expires:     time.Now().Add(24 * time.Hour),
		HTTPOnly:    true,
		SessionOnly: true,
	})
}

func mustCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return cidr
}

func nextIP(ip net.IP, cidr *net.IPNet) (net.IP, error) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
	if !cidr.Contains(ip) {
		return net.IPv4zero, fmt.Errorf("no more IPs in %s", cidr)
	}
	return ip, nil
}
