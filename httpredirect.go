package httpredirect

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})

	httpcaddyfile.RegisterHandlerDirective("redirect_if_cert_available", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("redirect_if_cert_available", httpcaddyfile.Before, "redir")
}

type Middleware struct {
	logger *zap.Logger
	tlsApp *caddytls.TLS
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.redirect_if_cert_available",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (h *Middleware) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}

	h.tlsApp = tlsAppIface.(*caddytls.TLS)

	if err != nil {
		return err
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := &Middleware{}

	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return handler, err
}

func (h *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

func (h *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	exists := h.tlsApp.HasCertificateForSubject(r.Host)

	h.logger.Debug(fmt.Sprintf("Checking certificate for %s: %t", r.Host, exists))

	if exists == true {
		h.logger.Debug(fmt.Sprintf("Certificate found for %s", r.Host))
		http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, r.RequestURI), http.StatusMovedPermanently)
	} else {
		h.logger.Warn(fmt.Sprintf("No certificate found for %s", r.Host))
		return next.ServeHTTP(w, r)
	}

	return nil
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
)
