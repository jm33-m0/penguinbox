// Command penguinboxd serves a LitterBox-compatible sandbox API inside a
// PenguinBox guest. It uploads artifacts, analyzes ELF images, detonates them
// in Podman, and returns Tracee and Falco telemetry.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"penguinbox/internal/sandbox"
)

func main() {
	var cfg sandbox.Config
	flag.StringVar(&cfg.Listen, "listen", "0.0.0.0:1338", "listen address; passt forwards the guest port 1338")
	flag.StringVar(&cfg.StateDir, "state-dir", "/var/lib/penguinbox", "upload and result directory")
	flag.StringVar(&cfg.FalcoLog, "falco-log", "/var/log/penguinbox/falco.json", "Falco JSON alert log")
	flag.StringVar(&cfg.Image, "image", "localhost/penguinbox-payload:latest", "payload runtime image")
	flag.StringVar(&cfg.PayloadNetwork, "payload-network", "", "optional Podman network mode for payload containers (e.g. none)")
	flag.StringVar(&cfg.APIToken, "api-token", "", "optional bearer token required for API requests")
	flag.StringVar(&cfg.Podman, "podman", "podman", "Podman binary")
	flag.StringVar(&cfg.HostAliasFile, "host-alias-file", "/mnt/penguinbox/host-internal", "file with the Podman host address behind host.containers.internal")
	flag.StringVar(&cfg.Tracee, "tracee", "/usr/local/bin/tracee", "Tracee binary")
	flag.StringVar(&cfg.TraceeHelper, "tracee-helper", "/usr/local/bin/penguinbox-tracee", "Tracee wrapper")
	flag.StringVar(&cfg.TraceeEvents, "tracee-events", sandbox.DefaultTraceeEvents, "Tracee event selection; use syscalls for every syscall")
	flag.StringVar(&cfg.YARA, "yara", "/usr/bin/yara", "YARA binary")
	flag.StringVar(&cfg.YARARules, "yara-rules", "/etc/penguinbox/rules/yara", "custom YARA rule directory")
	flag.StringVar(&cfg.FalcoRules, "falco-rules", "/etc/penguinbox/rules/falco", "custom Falco behavioral rule directory")
	flag.DurationVar(&cfg.DetonateTimeout, "detonate-timeout", 120*time.Second, "wall-clock limit for one payload")
	flag.Int64Var(&cfg.MaxUpload, "max-upload", 100<<20, "maximum upload size in bytes")
	flag.IntVar(&cfg.MaxEvents, "max-events", 100000, "maximum telemetry events stored per run")
	flag.Parse()

	if cfg.MaxUpload <= 0 {
		log.Fatal("max-upload must be positive")
	}
	if cfg.MaxEvents <= 0 {
		log.Fatal("max-events must be positive")
	}

	srv, err := sandbox.New(cfg)
	if err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer srv.Close()

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-sigCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	log.Printf("penguinboxd listening on %s", cfg.Listen)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}
