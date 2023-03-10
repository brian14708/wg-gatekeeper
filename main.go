package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/template/html"
	"google.golang.org/grpc"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/brian14708/wg-gatekeeper/models"
)

var (
	flagDBPath      = flag.String("db", "db.sqlite", "path to database")
	flagListen      = flag.String("listen", ":3000", "address to listen on")
	flagEnvoy       = flag.Bool("envoy", false, "enable envoy tcp proxy")
	flagEnvoyListen = flag.Int("envoy-listen", 9001, "port for envoy tcp proxy")
	flagEnvoyTcp    = flag.Int("envoy-tcp-proxy", 15000, "port for envoy tcp proxy")

	syncer *Syncer
)

func main() {
	flag.Parse()

	db, err := gorm.Open(sqlite.Open(*flagDBPath+"?_foreign_keys=on"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	models.Init(db)

	syncer = NewSyncer()
	syncer.UpdateInterface()

	if *flagEnvoy {
		grpcServer := grpc.NewServer()
		startLog(grpcServer)
		newXdsServer(grpcServer)

		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *flagEnvoyListen))
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		go grpcServer.Serve(l)
	}

	vfs := GetViews()
	engine := html.NewFileSystem(http.FS(vfs), ".html")
	engine.AddFuncMap(sprig.FuncMap())
	engine.Reload(Debug)

	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layouts/main",
	})

	app.Use(compress.New())
	app.Use("/assets", filesystem.New(filesystem.Config{
		Root:   http.FS(GetAssets()),
		MaxAge: int(time.Hour / time.Second),
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

	app.Listen(*flagListen)
}
