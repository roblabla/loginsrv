package caddy2

import (
	"strings"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/tarent/loginsrv/login"
)

// CaddyHandler is the loginsrv handler wrapper for caddy
type CaddyHandler struct {
	config       *login.Config
	loginHandler *login.Handler
}

func (h *CaddyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	//Fetch jwt token. If valid set a Caddy replacer for {user}
	userInfo, valid := h.loginHandler.GetToken(r)
	if valid {
		// let upstream middleware (e.g. fastcgi and cgi) know about authenticated
		// user; this replaces the request with a wrapped instance
		// TODO: impl this

		// Provide username to be used in log by replacer
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set("user", userInfo.Sub)
	}

	if strings.HasPrefix(r.URL.Path, h.config.LoginPath) {
		h.loginHandler.ServeHTTP(w, r)
		return nil
	}

	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*CaddyHandler)(nil)
)