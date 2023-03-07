package main

import (
	"flag"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/template/html"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/brian14708/wg-gatekeeper/models"
)

var (
	flagDBPath = flag.String("db", "db.sqlite", "path to database")
)

func main() {
	flag.Parse()

	db, err := gorm.Open(sqlite.Open(*flagDBPath+"?_foreign_keys=on"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	models.Init(db)

	vfs := GetViews()
	engine := html.NewFileSystem(http.FS(vfs), ".html")
	engine.AddFuncMap(sprig.FuncMap())
	engine.Reload(Debug)

	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layouts/main",
	})

	app.Use("/assets", filesystem.New(filesystem.Config{
		Root: http.FS(GetAssets()),
	}))

	instanceKey := strconv.Itoa(rand.Int())
	app.Use(func(c *fiber.Ctx) error {
		if c.Cookies("iface") != instanceKey {
			var cnt int64
			models.DB.Model(&models.Interface{}).Count(&cnt)
			if cnt == 0 {
				if c.Path() != "/interface" {
					flashInfo(c, "Please setup interface first")
					return c.Redirect("/interface")
				}
			} else {
				c.Cookie(&fiber.Cookie{
					Name:        "iface",
					Value:       instanceKey,
					Expires:     time.Now().Add(24 * time.Hour),
					HTTPOnly:    true,
					SessionOnly: true,
				})
			}
		}

		if c.Cookies("flash_error") != "" {
			c.Bind(fiber.Map{
				"FlashError": c.Cookies("flash_error"),
			})
			c.Cookie(&fiber.Cookie{
				Name:        "flash_error",
				Value:       "",
				Expires:     time.Now().Add(-time.Hour),
				HTTPOnly:    true,
				SessionOnly: true,
			})
		}
		if c.Cookies("flash_info") != "" {
			c.Bind(fiber.Map{
				"FlashInfo": c.Cookies("flash_info"),
			})
			c.Cookie(&fiber.Cookie{
				Name:        "flash_info",
				Value:       "",
				Expires:     time.Now().Add(-time.Hour),
				HTTPOnly:    true,
				SessionOnly: true,
			})

		}
		return c.Next()
	})

	appHandler(app)

	app.Listen(":3000")

	// var cfg Config
	// if _, err := toml.DecodeFile(*flagConfigPath, &cfg); err != nil {
	// 	log.Fatalf("parsing config: %v", err)
	// }

	// wg, err := wireguard.New(cfg.Interface.Name, cfg.Interface.PrivateKey, cfg.Interface.ListenPort)
	// if err != nil {
	// 	log.Fatalf("setting up interface: %v", err)
	// }
	// defer wg.Close()

	// for _, address := range cfg.Interface.Subnets {
	// 	if err := wg.AddrAdd(address); err != nil {
	// 		log.Fatalf("adding subnet (%v): %v", address, err)
	// 	}
	// }

	// for _, peer := range cfg.Clients {
	// 	if err := wg.PeerAdd(peer.PublicKey, peer.IP); err != nil {
	// 		log.Fatalf("adding peer (%v): %v", peer.PublicKey, err)
	// 	}
	// }

	// if cfg.Interface.NatForward != "" {
	// 	if err := wg.NatAdd(cfg.Interface.NatForward); err != nil {
	// 		log.Fatalf("adding nat (%v): %v", cfg.Interface.NatForward, err)
	// 	}
	// }

	// fmt.Println(wg.LinkIndex())

	// _, err = bwfilter.Attach(wg.LinkIndex())
	// if err != nil {
	// 	log.Fatalf("attaching filter: %v", err)
	// }
	// // defer l.Close()

	// if err := wg.LinkUp(); err != nil {
	// 	log.Fatalf("link up: %v", err)
	// }

}
