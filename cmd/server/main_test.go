package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestTheUIIsCompressedAndOnlyHashedFilesAreKept(t *testing.T) {
	script := strings.Repeat("console.log('sentinel');", 200)
	h := spaHandler(http.FS(fstest.MapFS{
		"index.html":          {Data: []byte("<html>the page</html>")},
		"assets/index-abc.js": {Data: []byte(script)},
	}))
	get := func(path string) *http.Response {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Result()
	}

	res := get("/assets/index-abc.js")
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("a hashed file: Cache-Control = %q", cc)
	}
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("a script was sent uncompressed")
	}
	zr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(zr); string(body) != script {
		t.Error("the script did not survive compression")
	}

	// The page, a route of the app, and a hashed file a newer build no
	// longer has: each is the page, and none of them is kept.
	for _, path := range []string{"/", "/policies/tracing", "/assets/index-old.js"} {
		res := get(path)
		if cc := res.Header.Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("%s: Cache-Control = %q", path, cc)
		}
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d", path, res.StatusCode)
		}
	}
}
