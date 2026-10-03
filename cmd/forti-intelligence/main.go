package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/mcpserver"
	"github.com/synit-io/forti-intelligence/internal/service"
)

// version is set with -X main.version at link time. The default matches
// mcpserver.ServerVersion.
var version = "0.1.0"

func main() {
	configPath := flag.String("config", "", "YAML configuration path; FORTI_INTELLIGENCE_CONFIG is used when empty. Also checked in XDG locations: ~/.config/forti-intelligence/config.yaml, /etc/forti-intelligence/config.yaml")
	transport := flag.String("transport", "stdio", "transport: stdio or http")
	listen := flag.String("listen", "", "HTTP listen address override")
	debug := flag.Bool("debug", false, "Enable debug-level logging")
	logJSON := flag.Bool("log-json", false, "Write logs as JSON. FORTI_INTELLIGENCE_LOG_JSON=1 does the same.")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	healthcheck := flag.String("healthcheck", "", "GET this URL and exit 0 only when it returns HTTP 200. Sends Authorization: Bearer from FORTI_MCP_HTTP_TOKEN when that variable is set.")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Forti Intelligence MCP Server version %s\n", version)
		os.Exit(0)
	}
	if strings.TrimSpace(*healthcheck) != "" {
		os.Exit(runHealthcheck(*healthcheck))
	}

	// Determine log level
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	logOptions := &slog.HandlerOptions{Level: logLevel}
	var logHandler slog.Handler = slog.NewTextHandler(os.Stderr, logOptions)
	if *logJSON || logJSONRequested() {
		logHandler = slog.NewJSONHandler(os.Stderr, logOptions)
	}
	logger := slog.New(logHandler)
	// Note: Fortinet clients log slow requests through their own logger parameter.
	// We avoid using slog.SetDefault() to prevent global state mutation.
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(2)
	}
	if *listen != "" {
		cfg.Server.ListenAddress = *listen
	}
	if err := cfg.Validate(); err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(2)
	}
	if err := config.ValidateHTTPExposure(*transport, cfg.Server.ListenAddress, cfg.Server.HTTPBearerToken, cfg.Server.HTTPTrustedProxy); err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(2)
	}
	logEffectiveConfiguration(logger, *configPath, cfg)

	managers, analyzers, closeClients, err := buildClients(cfg, logger)
	if err != nil {
		logger.Error("client setup failed", "error", err)
		os.Exit(2)
	}
	// Exit only after the deferred cleanup below has logged out of the
	// appliances: os.Exit skips deferred calls. Registered first, runs last.
	exitCode := 0
	defer func() {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()
	defer func() {
		if err := closeClients(); err != nil {
			logger.Warn("client shutdown failed", "error", err)
		}
	}()

	healthManagers = managers
	store := inventory.NewStore(managers, cfg.RefreshIntervalDuration(), cfg.Server.MaxConcurrentCalls)
	store.SetRefreshTimeout(cfg.RefreshTimeoutDuration())
	store.SetLogger(logger)
	app := service.New(cfg, store, managers, analyzers)
	if cfg.Rating.HasDedicatedCredentials() {
		// The dedicated rating account shares the FortiManager connection
		// settings of its profile but only ever sends the rating lookup.
		ratingProfile, err := cfg.RatingProfile()
		if err != nil {
			logger.Error("rating account setup failed", "error", err)
			exitCode = 2
			return
		}
		ratingClient, err := fortinet.NewFortiManagerRatingClient(ratingProfile)
		if err != nil {
			logger.Error("rating account setup failed", "error", err)
			exitCode = 2
			return
		}
		defer func() {
			if err := ratingClient.Close(); err != nil {
				logger.Warn("rating account logout failed", "error", err)
			}
		}()
		app.SetRatingClient(strings.TrimSuffix(ratingProfile.Name, "/rating"), ratingClient)
	}
	mcpServer := mcpserver.New(app, cfg.Server, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Inventory loads in the background so the MCP transport answers at once;
	// tools report "still loading" until the first snapshot is published.
	store.Start(ctx)
	// Stop the refresh loop first, then wait for refresh_inventory and web
	// filter loads, then close clients. Defers run in reverse order.
	defer app.WaitBackground()
	defer store.Stop()
	logger.Info("inventory refresh started in background", "refresh_interval", cfg.RefreshIntervalDuration(), "refresh_timeout", cfg.RefreshTimeoutDuration())

	switch strings.ToLower(strings.TrimSpace(*transport)) {
	case "stdio":
		if err := mcpServer.RunStdio(ctx); err != nil && ctx.Err() == nil {
			logger.Error("stdio server stopped", "error", err)
			exitCode = 1
			return
		}
	case "http", "streamable-http", "streamable_http":
		// Web filter lookups and refreshes may run for the refresh timeout;
		// the HTTP write deadline must not cut their responses short.
		writeTimeout := max(2*time.Minute, cfg.RefreshTimeoutDuration()+30*time.Second)
		// Use a generous shutdown timeout to allow in-flight requests to complete
		shutdownTimeout := 30 * time.Second
		if err := runHTTP(ctx, mcpServer, cfg.Server.ListenAddress, cfg.Server.MCPPath, cfg.Server.HTTPBearerToken, writeTimeout, shutdownTimeout, logger, func() map[string]any { return inventoryHealth(store) }, func() bool { return inventoryReady(store) }); err != nil {
			logger.Error("HTTP server stopped", "error", err)
			exitCode = 1
			return
		}
	default:
		logger.Error("unknown transport", "transport", *transport)
		exitCode = 2
		return
	}
}

func logEffectiveConfiguration(logger *slog.Logger, flagPath string, cfg config.Config) {
	source := strings.TrimSpace(flagPath)
	if source == "" {
		source = strings.TrimSpace(os.Getenv("FORTI_INTELLIGENCE_CONFIG"))
	}
	if source == "" {
		source = "<defaults>"
	}
	logger.Info("configuration loaded", "source", source, "profiles", len(cfg.Profiles))
	for _, profile := range cfg.Profiles {
		scope := "unrestricted"
		attrs := []any{"profile", profile.Name, "product", profile.Product}
		if len(profile.ADOMs) > 0 {
			scope = "allowlist"
			attrs = append(attrs, "adoms", profile.ADOMs)
		}
		attrs = append(attrs, "adom_scope", scope)
		logger.Info("profile ADOM scope", attrs...)
	}
	rating := []any{}
	if cfg.Rating.Device != "" {
		rating = append(rating, "device", cfg.Rating.Device)
	}
	if cfg.Rating.HasDedicatedCredentials() {
		rating = append(rating, "account", "dedicated rating account")
	}
	if len(rating) > 0 {
		logger.Info("FortiGuard rating through FortiManager", rating...)
		logger.Warn("FortiGuard URL rating (rate_url) requires JSON API Read-Write on FortiManager to proxy POST requests. Ensure either: (1) the FortiManager profile account has JSON API Read-Write, or (2) a dedicated rating account with Read-Write is configured via rating.api_key or rating.username/password. Without this, rate_url will fail with permission denied.")
	}
}

func buildClients(cfg config.Config, logger *slog.Logger) (map[string]fortinet.Manager, map[string]fortinet.Analyzer, func() error, error) {
	managers := make(map[string]fortinet.Manager)
	analyzers := make(map[string]fortinet.Analyzer)
	closeBuilt := func() error {
		var firstErr error
		for name, client := range managers {
			if err := client.Close(); err != nil && firstErr == nil {
				logger.Warn("FortiManager logout failed", "profile", name, "error", err)
				firstErr = err
			}
		}
		for name, client := range analyzers {
			if err := client.Close(); err != nil && firstErr == nil {
				logger.Warn("FortiAnalyzer logout failed", "profile", name, "error", err)
				firstErr = err
			}
		}
		return firstErr
	}
	for _, profile := range cfg.Profiles {
		var err error
		switch profile.Product {
		case config.ProductFortiManager:
			var client fortinet.Manager
			client, err = fortinet.NewFortiManager(profile)
			if err == nil {
				managers[profile.Name] = client
			}
		case config.ProductFortiAnalyzer:
			var client fortinet.Analyzer
			client, err = fortinet.NewFortiAnalyzer(profile)
			if err == nil {
				analyzers[profile.Name] = client
			}
		}
		if err != nil {
			_ = closeBuilt()
			return nil, nil, func() error { return nil }, err
		}
	}
	return managers, analyzers, closeBuilt, nil
}

// healthManagers lets /healthz report per-profile transient denials.
var healthManagers map[string]fortinet.Manager

// inventoryReady is true once the first snapshot has been published. A later
// refresh keeps serving that snapshot, so the process stays ready.
func inventoryReady(store *inventory.Store) bool {
	return store.HasSnapshot()
}

// inventoryHealth summarizes inventory readiness for /healthz. The endpoint
// stays HTTP 200 while the process serves requests; readiness and stale
// profiles are reported in the body for monitoring.
func inventoryHealth(store *inventory.Store) map[string]any {
	snapshot := store.Snapshot()
	stale := make([]string, 0)
	for _, profile := range snapshot.Profiles {
		if profile.Stale {
			stale = append(stale, profile.Profile)
		}
	}
	health := map[string]any{
		"inventory_ready":     !snapshot.GeneratedAt.IsZero(),
		"refresh_in_progress": snapshot.RefreshInProgress,
		"devices":             len(snapshot.Devices),
		"unavailable_devices": len(snapshot.UnavailableDevices),
		"refresh_errors":      len(snapshot.Errors),
		"stale_profiles":      stale,
	}
	transient := make(map[string]int64)
	for name, manager := range healthManagers {
		if counter, ok := manager.(interface{ TransientDenials() int64 }); ok && counter.TransientDenials() > 0 {
			transient[name] = counter.TransientDenials()
		}
	}
	if len(transient) > 0 {
		// Denials that vanished on re-check mean another client uses the same
		// API credential concurrently; give each server its own API account.
		health["transient_permission_denials"] = transient
	}
	if !snapshot.GeneratedAt.IsZero() {
		health["inventory_generated_at"] = snapshot.GeneratedAt.UTC()
		health["inventory_age_seconds"] = int(time.Since(snapshot.GeneratedAt).Seconds())
		health["last_refresh_duration_seconds"] = store.LastRefreshDuration().Seconds()
	}
	return health
}

func runHTTP(ctx context.Context, mcpServer *mcpserver.Server, address, mcpPath, bearerToken string, writeTimeout, shutdownTimeout time.Duration, logger *slog.Logger, health func() map[string]any, ready func() bool) error {
	mux := newHTTPMux(mcpServer.StreamableHTTPHandler(), mcpPath, bearerToken, mcpServer, health, ready)
	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       2 * time.Minute,
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	defer server.Close()
	errCh := make(chan error, 1)
	go func() {
		logger.Info("streamable HTTP server listening", "address", listener.Addr().String(), "path", mcpPath)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		logger.Info("HTTP server shutting down gracefully", "timeout", shutdownTimeout)
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == nil {
			return fmt.Errorf("HTTP listener exited")
		}
		return err
	}
}

// newHTTPMux serves MCP and the operational routes. When bearerToken is set,
// /healthz, /ready, and /metrics require it. The MCP handler authenticates
// itself, including when the token is empty.
func newHTTPMux(mcpHandler http.Handler, mcpPath, bearerToken string, mcp *mcpserver.Server, health func() map[string]any, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(mcpPath, mcpHandler)
	mux.Handle("/healthz", mcpserver.Authorize(bearerToken, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{"ok": true, "time": time.Now().UTC()}
		if health != nil {
			maps.Copy(body, health())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})))
	mux.Handle("/ready", mcpserver.Authorize(bearerToken, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if ready != nil && !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ready": false, "reason": "inventory not ready"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ready": true})
	})))
	mux.Handle("/metrics", mcpserver.Authorize(bearerToken, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var snapshot map[string]any
		if health != nil {
			snapshot = health()
		}
		if mcp == nil {
			return
		}
		_, _ = io.WriteString(w, mcp.Prometheus(snapshot))
	})))
	return mux
}

func logJSONRequested() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FORTI_INTELLIGENCE_LOG_JSON"))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// runHealthcheck is the process probe used by the container HEALTHCHECK.
// Distroless has no shell or wget. Exit 0 only on HTTP 200.
func runHealthcheck(rawURL string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	if token := strings.TrimSpace(os.Getenv("FORTI_MCP_HTTP_TOKEN")); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: HTTP %d\n", response.StatusCode)
		return 1
	}
	return 0
}
