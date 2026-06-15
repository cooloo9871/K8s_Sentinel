package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"github.com/cooloo9871/sentinel/internal/admission"
	"github.com/cooloo9871/sentinel/internal/alert"
	"github.com/cooloo9871/sentinel/internal/auth"
	"github.com/cooloo9871/sentinel/internal/handler"
	"github.com/cooloo9871/sentinel/internal/rsyslog"
	"github.com/cooloo9871/sentinel/internal/webhook"
	k8sclient "github.com/cooloo9871/sentinel/internal/k8s"
	sentinelweb "github.com/cooloo9871/sentinel/web"
)

func main() {
	dynClient, typedClient, restCfg, err := k8sclient.NewClients()
	if err != nil {
		log.Fatalf("k8s clients: %v", err)
	}

	store := k8sclient.NewStore(dynClient, typedClient, restCfg)
	store.StartDiscoveryLoop(context.Background())

	users := auth.NewUserStore("/data/sentinel/users.json")
	secret, err := auth.LoadOrCreateSecret("/data/sentinel/.jwt-secret")
	if err != nil {
		log.Fatalf("jwt secret: %v", err)
	}

	alerts := alert.NewStore("/data/sentinel/alerts.json")
	dispatcher := alert.NewDispatcher(alerts, store)
	go dispatcher.Run(context.Background())

	rsyslogs := rsyslog.NewStore("/data/sentinel/rsyslog.json")
	rsyslogDispatch := rsyslog.NewDispatcher(rsyslogs, store)
	go rsyslogDispatch.Run(context.Background())

	admissionStore := admission.NewStore()
	go admissionStore.Run(context.Background(), typedClient)

	admissionRules := admission.NewRuleStore("/data/sentinel/admission-rules.json")

	// Start admission webhook server (HTTPS :8443)
	tlsBundle, err := webhook.LoadOrCreate(
		"/data/sentinel/webhook-tls.crt",
		"/data/sentinel/webhook-tls.key",
		"/data/sentinel/webhook-ca.crt",
		[]string{
			"sentinel.sentinel-system.svc",
			"sentinel.sentinel-system.svc.cluster.local",
		},
	)
	if err != nil {
		log.Fatalf("webhook tls: %v", err)
	}
	evaluator := webhook.NewEvaluator(admissionRules)
	admHandler := webhook.NewAdmissionHandler(evaluator, admissionStore)
	go func() {
		if err := webhook.StartHTTPS(context.Background(), ":8443", tlsBundle, admHandler); err != nil {
			log.Printf("webhook server: %v", err)
		}
	}()
	// Register ValidatingWebhookConfiguration
	go func() {
		if err := webhook.Register(context.Background(), typedClient, tlsBundle.CACert, "sentinel-system", "sentinel"); err != nil {
			log.Printf("webhook register: %v", err)
		}
	}()

	cfg := handler.Config{
		Store:           store,
		Users:           users,
		Secret:          secret,
		Alerts:          alerts,
		Dispatcher:      dispatcher,
		Rsyslog:         rsyslogs,
		RsyslogDispatch: rsyslogDispatch,
		Admission:       admissionStore,
		AdmissionRules:  admissionRules,
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", handler.New(cfg))

	staticFS, err := fs.Sub(sentinelweb.StaticFiles, "dist")
	if err != nil {
		log.Fatalf("embed sub: %v", err)
	}
	mux.Handle("/", spaHandler(http.FS(staticFS)))

	log.Printf("starting sentinel on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
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
