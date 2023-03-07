package main

import (
	"flag"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/template/html"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/brian14708/wg-gatekeeper/models"
)

var (
	flagConfigPath = flag.String("config", "config.toml", "path to config file")
	flagDBPath     = flag.String("db", "wireguard.db", "path to database")
)

func main() {
	flag.Parse()

	db, err := gorm.Open(sqlite.Open(*flagDBPath), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	models.Init(db)

	vfs, reload := GetViews()
	engine := html.NewFileSystem(http.FS(vfs), ".html")
	if reload {
		engine.Reload(true)
	}

	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layouts/main",
	})

	app.Use("/assets", filesystem.New(filesystem.Config{
		Root: http.FS(GetAssets()),
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"Title": "Interfaces",
		})
	})

	app.Listen(":3000")

	return

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
