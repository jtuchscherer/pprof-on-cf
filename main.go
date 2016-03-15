package main

import (
	"encoding/base64"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"

	"net/http/pprof"

	"github.com/gorilla/mux"
)

type userProvider struct {
	username string
	password string
}

func (u *userProvider) credsMatch(username, password string) bool {
	return username == u.username && password == u.password
}

func main() {
	userProvider := userProvider{
		username: os.Getenv("USERNAME"),
		password: os.Getenv("PASSWORD"),
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r := mux.NewRouter()
	r.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	r.HandleFunc("/debug/pprof/", authenticate(http.HandlerFunc(pprof.Index), userProvider))
	r.HandleFunc("/debug/pprof/cmdline", authenticate(http.HandlerFunc(pprof.Cmdline), userProvider))
	r.HandleFunc("/debug/pprof/profile", authenticate(http.HandlerFunc(pprof.Profile), userProvider))
	r.HandleFunc("/debug/pprof/symbol", authenticate(http.HandlerFunc(pprof.Symbol), userProvider))

	r.HandleFunc("/debug/pprof/goroutine", authenticate(pprof.Handler("goroutine").ServeHTTP, userProvider))
	r.HandleFunc("/debug/pprof/heap", authenticate(pprof.Handler("heap").ServeHTTP, userProvider))
	r.HandleFunc("/debug/pprof/threadcreate", authenticate(pprof.Handler("threadcreate").ServeHTTP, userProvider))
	r.HandleFunc("/debug/pprof/block", authenticate(pprof.Handler("block").ServeHTTP, userProvider))

	log.Printf("About to listen to port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), r))
}

func authenticate(h http.HandlerFunc, userProvider userProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doAuthentication(w, r, h, userProvider)
	}
}

func doAuthentication(w http.ResponseWriter, r *http.Request, innerHandler func(w http.ResponseWriter, r *http.Request), userProvider userProvider) {
	w.Header().Set("WWW-Authenticate", `Basic realm="pprof"`)

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		http.Error(w, "Invalid authorization header", 401)
		return
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}

	credentials := strings.SplitN(string(b), ":", 2)
	if len(credentials) != 2 {
		http.Error(w, "Invalid authorization header", 401)
		return
	}

	if !userProvider.credsMatch(credentials[0], credentials[1]) {
		http.Error(w, "Not authorized", 401)
		return
	}

	innerHandler(w, r)
}
