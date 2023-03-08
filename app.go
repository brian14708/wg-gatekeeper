package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/brian14708/wg-gatekeeper/models"

	"github.com/gofiber/fiber/v2"
	"github.com/vishvananda/netlink"
	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

		if bw, err := strconv.ParseFloat(c.FormValue("bandwidth_in_limit"), 64); err != nil {
			flashError(c, "Invalid bandwidth limit")
			return c.Redirect("/")
		} else {
			acc.BandwidthInLimit = int64(bw * 1024 * 1024)
		}
		if bw, err := strconv.ParseFloat(c.FormValue("bandwidth_out_limit"), 64); err != nil {
			flashError(c, "Invalid bandwidth limit")
			return c.Redirect("/")
		} else {
			acc.BandwidthOutLimit = int64(bw * 1024 * 1024)
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

		if bw, err := strconv.ParseFloat(c.FormValue("bandwidth_in_limit"), 64); err != nil {
			flashError(c, "Invalid bandwidth limit")
			return c.Redirect("/")
		} else {
			acc.BandwidthInLimit = int64(bw * 1024 * 1024)
		}

		if bw, err := strconv.ParseFloat(c.FormValue("bandwidth_out_limit"), 64); err != nil {
			flashError(c, "Invalid bandwidth limit")
			return c.Redirect("/")
		} else {
			acc.BandwidthOutLimit = int64(bw * 1024 * 1024)
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

		ikey, err := wgtypes.NewKey(iface.PrivateKey)
		if err != nil {
			panic(err)
		}
		config := fmt.Sprintf(`[Interface]
Address = %s
PrivateKey = %s
DNS = 8.8.8.8
[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0`,
			cli.IPAddress,
			key.String(),
			ikey.PublicKey().String(),
			iface.ExternalIP,
			iface.ListenPort,
		)
		ret := models.DB.Create(&cli)
		if ret.Error != nil {
			flashError(c, ret.Error.Error())
			return c.Redirect("/account/" + c.Params("id"))
		}

		qrc, err := qrcode.NewWith(config, qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionLow))
		if err != nil {
			panic(err)
		}

		var buf bytes.Buffer
		w := standard.NewWithWriter(base64.NewEncoder(base64.StdEncoding, &buf), standard.WithQRWidth(8))
		if err = qrc.Save(w); err != nil {
			fmt.Printf("could not save image: %v", err)
		}

		syncer.UpdateClients()
		return c.Render("client", fiber.Map{
			"Client":    cli,
			"AccountID": c.Params("id"),
			"Config":    config,
			"QRCode":    buf.String(),
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
		for _, l := range links {
			a := l.Attrs()
			if a.Name == iface.Name || a.OperState == netlink.OperDown || a.Flags&net.FlagLoopback != 0 {
				continue
			}
			attrs = append(attrs, a)
		}

		return c.Render("interface", fiber.Map{
			"Iface": iface,
			"Links": attrs,
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
			if c.FormValue("home") != "" {
				return c.Redirect("/")
			} else {
				return c.Redirect("/interface")
			}
		}
	})

	// delete interface
	app.Get("/interface/:id/delete", func(c *fiber.Ctx) error {
		ret := models.DB.Unscoped().Delete(&models.Interface{}, c.Params("id"))
		if ret.Error != nil {
			flashError(c, ret.Error.Error())
		} else {
			flashInfo(c, "Interface deleted")
		}
		c.ClearCookie("iface")
		syncer.DeleteInterface()
		return c.Redirect("/interface")
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
