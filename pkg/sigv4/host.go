package sigv4

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// extractHost reconstructs the host the client signed into the canonical Host
// header. When the request arrives via a proxy/load balancer the client-signed
// host is carried in X-Forwarded-Host (with X-Forwarded-Port / X-Forwarded-Proto)
// while the Host header holds the proxy's address, so we prefer the forwarded
// values. The scheme's default port (80 for http, 443 for https) is stripped to
// match the AWS SDK's SanitizeHostForHeader — the value AWS clients actually sign.
//
// It is a port of SeaweedFS's extractHostHeader (minus the externalHost override),
// with scheme precedence adjusted for our request model: X-Forwarded-Proto beats
// the request URL scheme (we have no *tls.ConnectionState).
func extractHost(headers http.Header, u *url.URL) string {
	fwdHost := headers.Get("X-Forwarded-Host")
	fwdPort := firstHop(headers.Get("X-Forwarded-Port"))
	fwdProto := firstHop(headers.Get("X-Forwarded-Proto"))

	scheme := "http"
	if u.Scheme != "" {
		scheme = u.Scheme
	}
	if fwdProto != "" {
		scheme = fwdProto
	}

	rHost := headers.Get("Host")
	if rHost == "" {
		rHost = u.Host
	}

	var host, port string
	if fwdHost != "" {
		host = firstHop(fwdHost)
		if h, p, err := net.SplitHostPort(host); err == nil {
			// The forwarded host carries its own port — it wins over X-Forwarded-Port.
			host, port = h, p
		} else if rh, rp, err := net.SplitHostPort(rHost); err == nil && rh == host {
			// No port on the forwarded host, but the Host header names the same
			// hostname with a port — trust that port over a (possibly misreported)
			// X-Forwarded-Port.
			port = rp
		} else if fwdPort != "" {
			port = fwdPort
		}
	} else {
		host = rHost
		if h, p, err := net.SplitHostPort(host); err == nil {
			host, port = h, p
		} else if fwdPort != "" {
			port = fwdPort
		}
	}

	if port != "" && !isDefaultPort(scheme, port) {
		// Strip any existing brackets first: JoinHostPort re-adds them for IPv6, so
		// this avoids double-bracketing like [[::1]]:8080.
		host = strings.Trim(host, "[]")
		return net.JoinHostPort(host, port)
	}
	// No port, or a default port that was stripped. For IPv6 (contains ':') drop the
	// brackets to match the AWS SDK's bracket-less bare-host form.
	if strings.Contains(host, ":") {
		return strings.Trim(host, "[]")
	}
	return host
}

// firstHop returns the first comma-separated value, trimmed. X-Forwarded-* headers
// accumulate a value per proxy hop; the first is the original (client-facing) one.
func firstHop(v string) string {
	first, _, _ := strings.Cut(v, ",")
	return strings.TrimSpace(first)
}

// isDefaultPort reports whether port is the default for the scheme (80 for http,
// 443 for https), which the AWS SDK strips from the signed Host header.
func isDefaultPort(scheme, port string) bool {
	switch port {
	case "80":
		return strings.EqualFold(scheme, "http")
	case "443":
		return strings.EqualFold(scheme, "https")
	default:
		return false
	}
}
