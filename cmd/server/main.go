package main

import (
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/brobridge/sentinel/internal/handler"
	k8sclient "github.com/brobridge/sentinel/internal/k8s"
	sentinelweb "github.com/brobridge/sentinel/web"
)

func main() {
	dynClient, err := k8sclient.NewDynamicClient()
	if err != nil {
		log.Fatalf("k8s dynamic client: %v", err)
	}

	typedClient, err := k8sclient.NewTypedClient()
	if err != nil {
		log.Fatalf("k8s typed client: %v", err)
	}

	store := k8sclient.NewStore(dynClient, typedClient)

	cfg := handler.Config{
		Store: store,
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", handler.New(cfg))

	staticFS, err := fs.Sub(sentinelweb.StaticFiles, "dist")
	if err != nil {
		log.Fatalf("embed sub: %v", err)
	}
	mux.Handle("/", spaHandler(http.FS(staticFS)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("starting sentinel on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
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
