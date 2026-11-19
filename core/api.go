package core

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/config"
)

const Version = "0.1.0"

type apiServer struct {
	in     *Instance
	secret string
	listen string
	srv    *http.Server
	ln     net.Listener
}

func newAPI(in *Instance, c config.API) (*apiServer, error) {
	if c.Listen == "" {
		return nil, errors.New("api.listen is required")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return nil, errors.New("api.listen: " + err.Error())
	}
	if c.Secret == "" {
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("api.secret is required unless the API listens on loopback")
		}
	}
	a := &apiServer{in: in, secret: c.Secret, listen: c.Listen}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", a.version)
	mux.HandleFunc("GET /stats", a.stats)
	mux.HandleFunc("GET /connections", a.connections)
	mux.HandleFunc("DELETE /connections", a.killAll)
	mux.HandleFunc("DELETE /connections/{id}", a.kill)
	mux.HandleFunc("GET /outbounds", a.outbounds)
	mux.HandleFunc("PUT /outbounds/{tag}", a.choose)
	mux.HandleFunc("POST /dns/flush", a.flush)
	mux.HandleFunc("POST /reload", a.doReload)
	a.srv = &http.Server{Handler: a.auth(mux), ReadHeaderTimeout: 10 * time.Second}
	return a, nil
}

func (a *apiServer) start() error {
	ln, err := net.Listen("tcp", a.listen)
	if err != nil {
		return err
	}
	a.ln = ln
	go a.srv.Serve(ln)
	a.in.log.Info("api listening", "addr", ln.Addr().String())
	return nil
}

func (a *apiServer) close() { a.srv.Close() }

func (a *apiServer) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.secret != "" {
			tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(a.secret)) != 1 {
				reply(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (a *apiServer) version(w http.ResponseWriter, _ *http.Request) {
	reply(w, 200, map[string]string{"version": Version, "go": runtime.Version()})
}

func (a *apiServer) stats(w http.ResponseWriter, _ *http.Request) {
	t := a.in.tracker
	t.mu.Lock()
	live := len(t.flows)
	t.mu.Unlock()
	reply(w, 200, map[string]any{
		"uptime_seconds": int64(time.Since(a.in.started).Seconds()),
		"upload":         t.up.Load(),
		"download":       t.down.Load(),
		"active":         live,
		"total":          t.total.Load(),
		"goroutines":     runtime.NumGoroutine(),
	})
}

func (a *apiServer) connections(w http.ResponseWriter, _ *http.Request) {
	reply(w, 200, a.in.tracker.list())
}

func (a *apiServer) kill(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || !a.in.tracker.kill(id) {
		reply(w, 404, map[string]string{"error": "no such connection"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *apiServer) killAll(w http.ResponseWriter, _ *http.Request) {
	a.in.tracker.killAll()
	w.WriteHeader(http.StatusNoContent)
}

type outboundInfo struct {
	Tag     string   `json:"tag"`
	Type    string   `json:"type"`
	Now     string   `json:"now,omitempty"`
	Members []string `json:"members,omitempty"`
	Select  bool     `json:"selectable,omitempty"`
}

func (a *apiServer) outbounds(w http.ResponseWriter, _ *http.Request) {
	out := make([]outboundInfo, 0, len(a.in.order))
	for _, tag := range a.in.order {
		ob := a.in.outbounds[tag]
		info := outboundInfo{Tag: tag, Type: ob.Type()}
		if g, ok := ob.(adapter.Group); ok {
			info.Now = g.Now()
			for _, m := range g.Members() {
				info.Members = append(info.Members, m.Tag())
			}
			_, info.Select = ob.(adapter.Selector)
		}
		out = append(out, info)
	}
	reply(w, 200, out)
}

func (a *apiServer) choose(w http.ResponseWriter, r *http.Request) {
	sel, ok := a.in.outbounds[r.PathValue("tag")].(adapter.Selector)
	if !ok {
		reply(w, 404, map[string]string{"error": "not a selector"})
		return
	}
	var body struct {
		Select string `json:"select"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := sel.Select(body.Select); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *apiServer) flush(w http.ResponseWriter, _ *http.Request) {
	a.in.resolver.Flush()
	w.WriteHeader(http.StatusNoContent)
}

func (a *apiServer) doReload(w http.ResponseWriter, _ *http.Request) {
	if a.in.reload == nil {
		reply(w, 501, map[string]string{"error": "reload is not available"})
		return
	}
	w.WriteHeader(http.StatusAccepted)
	go a.in.reload()
}
