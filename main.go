package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/BurntSushi/toml"
	"github.com/charmbracelet/log"

	"github.com/brian14708/wg-gatekeeper/bwfilter"
	"github.com/brian14708/wg-gatekeeper/wireguard"
)

var (
	flagConfigPath = flag.String("config", "config.toml", "path to config file")
)

type Config struct {
	Interface struct {
		Name       string
		ListenPort int
		PrivateKey string
		Subnets    []string
	}
	Peers []struct {
		IP        string
		PublicKey string
	}
}

func main() {
	flag.Parse()

	var cfg Config
	if _, err := toml.DecodeFile(*flagConfigPath, &cfg); err != nil {
		log.Fatal("parsing config", "err", err)
	}

	wg, err := wireguard.New(cfg.Interface.Name, cfg.Interface.PrivateKey, cfg.Interface.ListenPort)
	if err != nil {
		log.Fatal("setting up interface", "err", err)
	}
	defer wg.Close()

	for _, address := range cfg.Interface.Subnets {
		if err := wg.AddrAdd(address); err != nil {
			log.Fatal("adding subnet", "subnet", address, "err", err)
		}
	}

	for _, peer := range cfg.Peers {
		if err := wg.PeerAdd(peer.PublicKey, peer.IP); err != nil {
			log.Fatal("adding peer", "peer", peer.PublicKey, "err", err)
		}
	}

	fmt.Println(wg.LinkIndex())

	_, err = bwfilter.Attach(wg.LinkIndex())
	if err != nil {
		log.Fatal("attaching filter", "err", err)
	}
	// defer l.Close()

	if err := wg.LinkUp(); err != nil {
		log.Fatal("link up", "err", err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	log.Info("RUNNING...")
	<-ch

	log.Info("SHUTTING DOWN...")
	signal.Reset(os.Interrupt)
}
