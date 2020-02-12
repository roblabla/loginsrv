package caddy2

import (
	"encoding/json"
	"flag"
	"errors"
	"fmt"
	"log"
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
	err := caddy.RegisterModule(CaddyHandler{})
	if err != nil {
		log.Fatal(err)
	}
	httpcaddyfile.RegisterDirective("login", parseCaddyfile)
}

func (CaddyHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.loginsrv",
		New: func() caddy.Module { return new(CaddyHandler) },
	}
}

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

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

func (c *CaddyHandler) UnmarshalJSON(b []byte) error {
	c.config = login.DefaultConfig()
	config_simple := LoginConfigSimple{}

	err := json.Unmarshal(b, &config_simple)
	if err != nil {
		return err
	}

	c.config.JwtSecret = config_simple.JwtSecret
	c.config.JwtSecretFile = config_simple.JwtSecretFile
	c.config.JwtAlgo = config_simple.JwtAlgo
	c.config.JwtExpiry = config_simple.JwtExpiry.Duration
	c.config.JwtRefreshes = config_simple.JwtRefreshes
	c.config.SuccessURL = config_simple.SuccessURL
	c.config.Redirect = config_simple.Redirect
	c.config.RedirectQueryParameter = config_simple.RedirectQueryParameter
	c.config.RedirectCheckReferer = config_simple.RedirectCheckReferer
	c.config.RedirectHostFile = config_simple.RedirectHostFile
	c.config.LogoutURL = config_simple.LogoutURL
	c.config.Template = config_simple.Template
	c.config.LoginPath = config_simple.LoginPath
	c.config.CookieName = config_simple.CookieName
	c.config.CookieExpiry = config_simple.CookieExpiry.Duration
	c.config.CookieDomain = config_simple.CookieDomain
	c.config.CookieHTTPOnly = config_simple.CookieHTTPOnly
	c.config.CookieSecure = config_simple.CookieSecure
	c.config.Backends = config_simple.Backends
	c.config.Oauth = config_simple.Oauth
	c.config.UserFile = config_simple.UserFile
	c.config.UserEndpoint = config_simple.UserEndpoint
	c.config.UserEndpointToken = config_simple.UserEndpointToken
	c.config.UserEndpointTimeout = config_simple.UserEndpointTimeout.Duration

	return nil
}

func (c *CaddyHandler) MarshalJSON() ([]byte, error) {
	config_simple := LoginConfigSimple{}

	config_simple.JwtSecret = c.config.JwtSecret
	config_simple.JwtSecretFile = c.config.JwtSecretFile
	config_simple.JwtAlgo = c.config.JwtAlgo
	config_simple.JwtExpiry = Duration{Duration: c.config.JwtExpiry}
	config_simple.JwtRefreshes = c.config.JwtRefreshes
	config_simple.SuccessURL = c.config.SuccessURL
	config_simple.Redirect = c.config.Redirect
	config_simple.RedirectQueryParameter = c.config.RedirectQueryParameter
	config_simple.RedirectCheckReferer = c.config.RedirectCheckReferer
	config_simple.RedirectHostFile = c.config.RedirectHostFile
	config_simple.LogoutURL = c.config.LogoutURL
	config_simple.Template = c.config.Template
	config_simple.LoginPath = c.config.LoginPath
	config_simple.CookieName = c.config.CookieName
	config_simple.CookieExpiry = Duration{Duration: c.config.CookieExpiry}
	config_simple.CookieDomain = c.config.CookieDomain
	config_simple.CookieHTTPOnly = c.config.CookieHTTPOnly
	config_simple.CookieSecure = c.config.CookieSecure
	config_simple.Backends = c.config.Backends
	config_simple.Oauth = c.config.Oauth
	config_simple.UserFile = c.config.UserFile
	config_simple.UserEndpoint = c.config.UserEndpoint
	config_simple.UserEndpointToken = c.config.UserEndpointToken
	config_simple.UserEndpointTimeout = Duration{Duration: c.config.UserEndpointTimeout}

	data, err := json.Marshal(config_simple)
	return data, err
}

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

		handler := CaddyHandler { config: config }
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
