package main

import (
	"encoding/base64"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"

	"net/http/httputil"
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
	up := userProvider{
		username: os.Getenv("USERNAME"),
		password: os.Getenv("PASSWORD"),
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r := mux.NewRouter()
	r.HandleFunc("/dumpReq", func(w http.ResponseWriter, r *http.Request) {
		reqBytes, err := httputil.DumpRequest(r, false)
		if err != nil {
			log.Printf("Not able to print request: %q", err.Error)
			fmt.Fprintf(w, "Not able to print request: %q", err.Error)
		}
		log.Printf("X-Vcap-Request-Id Header %s", r.Header.Get("X-Vcap-Request-Id"))
		fmt.Fprintf(w, "Whole Request %s", reqBytes)
		fmt.Fprintf(w, "Hello, %q\n", html.EscapeString(r.URL.Path))
	})

	r.HandleFunc("/debug/pprof/", authenticate(http.HandlerFunc(pprof.Index), up))
	r.HandleFunc("/debug/pprof/cmdline", authenticate(http.HandlerFunc(pprof.Cmdline), up))
	r.HandleFunc("/debug/pprof/profile", authenticate(http.HandlerFunc(pprof.Profile), up))
	r.HandleFunc("/debug/pprof/symbol", authenticate(http.HandlerFunc(pprof.Symbol), up))

	r.HandleFunc("/debug/pprof/goroutine", authenticate(pprof.Handler("goroutine").ServeHTTP, up))
	r.HandleFunc("/debug/pprof/heap", authenticate(pprof.Handler("heap").ServeHTTP, up))
	r.HandleFunc("/debug/pprof/threadcreate", authenticate(pprof.Handler("threadcreate").ServeHTTP, up))
	r.HandleFunc("/debug/pprof/block", authenticate(pprof.Handler("block").ServeHTTP, up))

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
