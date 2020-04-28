package caddy2

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/tarent/loginsrv/login"

	// Import all backends, packaged with the caddy plugin
	_ "github.com/tarent/loginsrv/htpasswd"
	_ "github.com/tarent/loginsrv/httpupstream"
	_ "github.com/tarent/loginsrv/oauth2"
	_ "github.com/tarent/loginsrv/osiam"
)

func init() {
	caddy.RegisterModule(CaddyHandler{})
	httpcaddyfile.RegisterDirective("login", parseCaddyfile)
}

// CaddyModule returns a definition of the module, and is the only required
// method for the Caddy Module interface.
func (CaddyHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.loginsrv",
		New: func() caddy.Module { return new(CaddyHandler) },
	}
}

// Duration is a wrapper around time.Duration to make JSON marshaling work
// correctly with JWT.
type Duration struct {
	time.Duration
}

// MarshalJSON turns the duration into a json byte array.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON turns the byte array into a Duration.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

// LoginConfigSimple holds all of our possible config arguments.
type LoginConfigSimple struct {
	JwtSecret              string        `json:"jwt_secret,omitempty"`
	JwtSecretFile          string        `json:"jwt_secret_file,omitempty"`
	JwtAlgo                string        `json:"jwt_algo,omitempty"`
	JwtExpiry              Duration      `json:"jwt_expiry,omitempty"`
	JwtRefreshes           int           `json:"jwt_refreshes,omitempty"`
	SuccessURL             string        `json:"successful_url,omitempty"`
	Redirect               bool          `json:"redirect,omitempty"`
	RedirectQueryParameter string        `json:"redirect_query_parameter,omitempty"`
	RedirectCheckReferer   bool          `json:"redirect_check_referer,omitempty"`
	RedirectHostFile       string        `json:"redirect_host_file,omitempty"`
	LogoutURL              string        `json:"logout_url,omitempty"`
	Template               string        `json:"template,omitempty"`
	LoginPath              string        `json:"login_path,omitempty"`
	CookieName             string        `json:"cookie_name,omitempty"`
	CookieExpiry           Duration      `json:"cookie_expiry,omitempty"`
	CookieDomain           string        `json:"cookie_domain,omitempty"`
	CookieHTTPOnly         bool          `json:"cookie_http_only,omitempty"`
	CookieSecure           bool          `json:"cookie_secure,omitempty"`
	Backends               login.Options `json:"backends,omitempty"`
	Oauth                  login.Options `json:"oauth,omitempty"`
	UserFile               string        `json:"user_file,omitempty"`
	UserEndpoint           string        `json:"user_endpoint,omitempty"`
	UserEndpointToken      string        `json:"user_endpoint_token,omitempty"`
	UserEndpointTimeout    Duration      `json:"user_endpoint_timeout,omitempty"`
}

// UnmarshalJSON turns a byte array into a configured CaddyHandler.
func (c *CaddyHandler) UnmarshalJSON(b []byte) error {
	c.config = login.DefaultConfig()
	configSimple := LoginConfigSimple{}

	err := json.Unmarshal(b, &configSimple)
	if err != nil {
		return err
	}

	c.config.JwtSecret = configSimple.JwtSecret
	c.config.JwtSecretFile = configSimple.JwtSecretFile
	c.config.JwtAlgo = configSimple.JwtAlgo
	c.config.JwtExpiry = configSimple.JwtExpiry.Duration
	c.config.JwtRefreshes = configSimple.JwtRefreshes
	c.config.SuccessURL = configSimple.SuccessURL
	c.config.Redirect = configSimple.Redirect
	c.config.RedirectQueryParameter = configSimple.RedirectQueryParameter
	c.config.RedirectCheckReferer = configSimple.RedirectCheckReferer
	c.config.RedirectHostFile = configSimple.RedirectHostFile
	c.config.LogoutURL = configSimple.LogoutURL
	c.config.Template = configSimple.Template
	c.config.LoginPath = configSimple.LoginPath
	c.config.CookieName = configSimple.CookieName
	c.config.CookieExpiry = configSimple.CookieExpiry.Duration
	c.config.CookieDomain = configSimple.CookieDomain
	c.config.CookieHTTPOnly = configSimple.CookieHTTPOnly
	c.config.CookieSecure = configSimple.CookieSecure
	c.config.Backends = configSimple.Backends
	c.config.Oauth = configSimple.Oauth
	c.config.UserFile = configSimple.UserFile
	c.config.UserEndpoint = configSimple.UserEndpoint
	c.config.UserEndpointToken = configSimple.UserEndpointToken
	c.config.UserEndpointTimeout = configSimple.UserEndpointTimeout.Duration

	return nil
}

// MarshalJSON turns a CaddyHandler into a json byte array.
func (c *CaddyHandler) MarshalJSON() ([]byte, error) {
	configSimple := LoginConfigSimple{}

	configSimple.JwtSecret = c.config.JwtSecret
	configSimple.JwtSecretFile = c.config.JwtSecretFile
	configSimple.JwtAlgo = c.config.JwtAlgo
	configSimple.JwtExpiry = Duration{Duration: c.config.JwtExpiry}
	configSimple.JwtRefreshes = c.config.JwtRefreshes
	configSimple.SuccessURL = c.config.SuccessURL
	configSimple.Redirect = c.config.Redirect
	configSimple.RedirectQueryParameter = c.config.RedirectQueryParameter
	configSimple.RedirectCheckReferer = c.config.RedirectCheckReferer
	configSimple.RedirectHostFile = c.config.RedirectHostFile
	configSimple.LogoutURL = c.config.LogoutURL
	configSimple.Template = c.config.Template
	configSimple.LoginPath = c.config.LoginPath
	configSimple.CookieName = c.config.CookieName
	configSimple.CookieExpiry = Duration{Duration: c.config.CookieExpiry}
	configSimple.CookieDomain = c.config.CookieDomain
	configSimple.CookieHTTPOnly = c.config.CookieHTTPOnly
	configSimple.CookieSecure = c.config.CookieSecure
	configSimple.Backends = c.config.Backends
	configSimple.Oauth = c.config.Oauth
	configSimple.UserFile = c.config.UserFile
	configSimple.UserEndpoint = c.config.UserEndpoint
	configSimple.UserEndpointToken = c.config.UserEndpointToken
	configSimple.UserEndpointTimeout = Duration{Duration: c.config.UserEndpointTimeout}

	data, err := json.Marshal(configSimple)
	return data, err
}

// Provision pulls the config out of context and sets it on the handler.
func (c *CaddyHandler) Provision(context caddy.Context) error {
	loginHandler, err := login.NewHandler(c.config)
	if err != nil {
		return err
	}
	_, secretFromEnvWasSetBefore := os.LookupEnv("JWT_SECRET")
	if !secretFromEnvWasSetBefore {
		// populate the secret to caddy.jwt,
		// but do not change a environment variable if already set.
		os.Setenv("JWT_SECRET", c.config.JwtSecret)
	}
	c.loginHandler = loginHandler
	return nil
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     login {
//          TODO: Document this
//     }
//
// If no hash algorithm is supplied, bcrypt will be assumed.w loginsrv instance.
func parseCaddyfile(c httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	for c.Next() {
		config, err := parseConfig(&c)
		if err != nil {
			return nil, err
		}

		if config.Template != "" && !filepath.IsAbs(config.Template) {
			config.Template = filepath.Join(c.File(), config.Template)
		}

		handler := CaddyHandler{config: config}
		return c.NewRoute(nil, &handler), nil
	}
	return nil, c.ArgErr()
}

func parseConfig(c *httpcaddyfile.Helper) (*login.Config, error) {
	cfg := login.DefaultConfig()
	cfg.Host = ""
	cfg.Port = ""
	cfg.LogLevel = ""

	fs := flag.NewFlagSet("loginsrv-config", flag.ContinueOnError)
	cfg.ConfigureFlagSet(fs)

	secretProvidedByConfig := false
	for c.NextBlock(0) {
		// caddy prefers '_' in parameter names,
		// so we map them to the '-' from the command line flags
		// the replacement supports both, for backwards compatibility
		name := strings.Replace(c.Val(), "_", "-", -1)
		args := c.RemainingArgs()
		if len(args) != 1 {
			return cfg, fmt.Errorf("Wrong number of arguments for %v: %v (%v:%v)", name, args, c.File(), c.Line())
		}
		value := args[0]

		f := fs.Lookup(name)
		if f == nil {
			return cfg, fmt.Errorf("Unknown parameter for login directive: %v (%v:%v)", name, c.File(), c.Line())
		}
		err := f.Value.Set(value)
		if err != nil {
			return cfg, fmt.Errorf("Invalid value for parameter %v: %v (%v:%v)", name, value, c.File(), c.Line())
		}

		if name == "jwt-secret" {
			secretProvidedByConfig = true
		}
	}

	if err := cfg.ResolveFileReferences(); err != nil {
		return nil, err
	}

	secretFromEnv, secretFromEnvWasSetBefore := os.LookupEnv("JWT_SECRET")
	if !secretProvidedByConfig && secretFromEnvWasSetBefore {
		cfg.JwtSecret = secretFromEnv
	}

	return cfg, nil
}
