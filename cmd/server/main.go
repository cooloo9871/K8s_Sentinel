package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cooloo9871/sentinel/internal/admission"
	"github.com/cooloo9871/sentinel/internal/alert"
	"github.com/cooloo9871/sentinel/internal/auth"
	"github.com/cooloo9871/sentinel/internal/handler"
	"github.com/cooloo9871/sentinel/internal/rsyslog"
	"github.com/cooloo9871/sentinel/internal/security"
	k8sclient "github.com/cooloo9871/sentinel/internal/k8s"
	sentinelweb "github.com/cooloo9871/sentinel/web"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dynClient, typedClient, restCfg, err := k8sclient.NewClients()
	if err != nil {
		log.Fatalf("k8s clients: %v", err)
	}

	store := k8sclient.NewStore(dynClient, typedClient, restCfg)
	store.StartDiscoveryLoop(ctx)
	// Single Tetragon broadcast — security store, alert and rsyslog
	// dispatchers all subscribe to this rather than opening independent streams.
	store.StartTetragonBroadcast(ctx)

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data/sentinel"
	}
	// Warn early if the data directory is not writable — events would silently
	// exist only in memory and be lost on restart without this notice.
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		log.Printf("WARNING: cannot create data directory %s: %v — data will not be persisted", dataDir, err)
	} else {
		probe := dataDir + "/.write-probe"
		if err := os.WriteFile(probe, []byte{}, 0600); err != nil {
			log.Printf("WARNING: data directory %s is not writable: %v — data will not be persisted", dataDir, err)
		} else {
			_ = os.Remove(probe)
		}
	}
	data := func(name string) string { return dataDir + "/" + name }

	users := auth.NewUserStore(data("users.json"))
	secret, err := auth.LoadOrCreateSecret(data(".jwt-secret"))
	if err != nil {
		log.Fatalf("jwt secret: %v", err)
	}

	admissionStore := admission.NewStore(data("admission-events.json"))
	go admissionStore.Run(ctx, typedClient)

	securityStore := security.NewStore(data("security-events.json"))
	go securityStore.Run(ctx, store)

	alerts := alert.NewStore(data("alerts.json"))
	dispatcher := alert.NewDispatcher(alerts, store, admissionStore)
	go dispatcher.Run(ctx)

	rsyslogs := rsyslog.NewStore(data("rsyslog.json"))
	rsyslogDispatch := rsyslog.NewDispatcher(rsyslogs, store, admissionStore)
	go rsyslogDispatch.Run(ctx)

	cfg := handler.Config{
		Store:           store,
		Users:           users,
		Secret:          secret,
		Alerts:          alerts,
		Dispatcher:      dispatcher,
		Rsyslog:         rsyslogs,
		RsyslogDispatch: rsyslogDispatch,
		Admission:       admissionStore,
		Security:        securityStore,
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", handler.New(cfg))

	staticFS, err := fs.Sub(sentinelweb.StaticFiles, "dist")
	if err != nil {
		log.Fatalf("embed sub: %v", err)
	}
	mux.Handle("/", spaHandler(http.FS(staticFS)))

	srv := &http.Server{Addr: ":8080", Handler: mux}
	go func() {
		log.Printf("starting sentinel on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
	log.Printf("shutdown complete")
}

func spaHandler(fsys http.FileSystem) http.Handler {
	fileServer := http.FileServer(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := fsys.Open(r.URL.Path)
		if err != nil {
			r.URL.Path = "/"
		} else {
			f.Close()
		}
		fileServer.ServeHTTP(w, r)
	})
}
