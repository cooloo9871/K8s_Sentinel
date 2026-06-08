package main

import (
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/cooloo9871/sentinel/internal/handler"
	k8sclient "github.com/cooloo9871/sentinel/internal/k8s"
	sentinelweb "github.com/cooloo9871/sentinel/web"
)

func main() {
	dynClient, typedClient, restCfg, err := k8sclient.NewClients()
	if err != nil {
		log.Fatalf("k8s clients: %v", err)
	}

	store := k8sclient.NewStore(dynClient, typedClient, restCfg)

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
