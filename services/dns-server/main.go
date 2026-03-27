package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/darkhal/autarch-dns/api"
	"github.com/darkhal/autarch-dns/config"
	"github.com/darkhal/autarch-dns/server"
)

var version = "2.1.0"

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	listenDNS := flag.String("dns", "", "DNS listen address (overrides config)")
	listenAPI := flag.String("api", "", "API listen address (overrides config)")
	apiToken := flag.String("token", "", "API auth token (overrides config)")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("autarch-dns v%s\n", version)
		os.Exit(0)
	}

	// Load config
	cfg := config.DefaultConfig()
	if data, err := os.ReadFile(*configPath); err == nil {
		if err := json.Unmarshal(data, cfg); err != nil {
			log.Printf("Warning: invalid config file: %v", err)
		}
	}

	// CLI overrides
	if *listenDNS != "" {
		cfg.ListenDNS = *listenDNS
	}
	if *listenAPI != "" {
		cfg.ListenAPI = *listenAPI
	}
	if *apiToken != "" {
		cfg.APIToken = *apiToken
	}

	// Initialize zone store
	store := server.NewZoneStore(cfg.ZonesDir)
	if err := store.LoadAll(); err != nil {
		log.Printf("Warning: loading zones: %v", err)
	}

	// Start DNS server
	dnsServer := server.NewDNSServer(cfg, store)
	go func() {
		log.Printf("DNS server listening on %s (UDP+TCP)", cfg.ListenDNS)
		if err := dnsServer.Start(); err != nil {
			log.Fatalf("DNS server error: %v", err)
		}
	}()

	// Start API server
	apiServer := api.NewAPIServer(cfg, store, dnsServer)
	go func() {
		log.Printf("API server listening on %s", cfg.ListenAPI)
		if err := apiServer.Start(); err != nil {
			log.Fatalf("API server error: %v", err)
		}
	}()

	log.Printf("autarch-dns v%s started", version)

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	dnsServer.Stop()
}
