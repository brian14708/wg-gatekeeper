package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/BurntSushi/toml"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/brian14708/wg-gatekeeper/bwfilter"
	"github.com/brian14708/wg-gatekeeper/models"
	"github.com/brian14708/wg-gatekeeper/wireguard"
)

var (
	flagConfigPath = flag.String("config", "config.toml", "path to config file")
	flagDbPath     = flag.String("db", "wireguard.db", "path to database")
)

type Config struct {
	Interface struct {
		Name       string
		ListenPort int
		PrivateKey string
		Subnets    []string
		NatForward string
	}
	Clients []struct {
		IP        string
		PublicKey string
	}
}

func main() {
	flag.Parse()

	db, err := gorm.Open(sqlite.Open(*flagDbPath), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	models.AutoMigrate(db)
	return

	var cfg Config
	if _, err := toml.DecodeFile(*flagConfigPath, &cfg); err != nil {
		log.Fatalf("parsing config: %v", err)
	}

	wg, err := wireguard.New(cfg.Interface.Name, cfg.Interface.PrivateKey, cfg.Interface.ListenPort)
	if err != nil {
		log.Fatalf("setting up interface: %v", err)
	}
	defer wg.Close()

	for _, address := range cfg.Interface.Subnets {
		if err := wg.AddrAdd(address); err != nil {
			log.Fatalf("adding subnet (%v): %v", address, err)
		}
	}

	for _, peer := range cfg.Clients {
		if err := wg.PeerAdd(peer.PublicKey, peer.IP); err != nil {
			log.Fatalf("adding peer (%v): %v", peer.PublicKey, err)
		}
	}

	if cfg.Interface.NatForward != "" {
		if err := wg.NatAdd(cfg.Interface.NatForward); err != nil {
			log.Fatalf("adding nat (%v): %v", cfg.Interface.NatForward, err)
		}
	}

	fmt.Println(wg.LinkIndex())

	_, err = bwfilter.Attach(wg.LinkIndex())
	if err != nil {
		log.Fatalf("attaching filter: %v", err)
	}
	// defer l.Close()

	if err := wg.LinkUp(); err != nil {
		log.Fatalf("link up: %v", err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	log.Print("RUNNING...")
	<-ch

	log.Print("SHUTTING DOWN...")
	signal.Reset(os.Interrupt)
}
