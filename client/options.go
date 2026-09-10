package client

import (
	"context"
	"time"

	"github.com/lingulingo/tlsprint/preset"
)

// ReqOption configures a single request. It is the functional-option cousin of
// the Request builder, so requests can be written curl_cffi-style:
//
//	resp, err := client.Get("https://example.com",
//	    client.Header("X-Api-Key", "secret"),
//	    client.Query("q", "tls"),
//	    client.Body(map[string]any{"a": 1}))
type ReqOption func(*Request)

// Impersonate selects the fingerprint preset at construction time (or in a
// top-level convenience call). It mirrors curl_cffi's `impersonate=`.
//
// It applies the preset through Client.SetBrowser so the preset's default
// headers (User-Agent, sec-ch-ua, Accept-Language, ...) are installed and the
// cached transports are rebuilt. Assigning the preset alone would leave the
// previous preset's headers in place.
func Impersonate(browser any) Option {
	return func(c *Client) {
		switch v := browser.(type) {
		case *preset.Preset:
			if v != nil {
				_ = c.SetBrowser(v)
			}
		case string:
			_ = c.SetBrowser(v)
		}
	}
}

// WithBrowser is an alias of Impersonate.
func WithBrowser(browser any) Option { return Impersonate(browser) }

// Header sets a request header.
func Header(key, value string) ReqOption {
	return func(r *Request) { r.headers.Set(key, value) }
}

// Headers sets several request headers from a map.
func Headers(headers map[string]string) ReqOption {
	return func(r *Request) {
		for k, v := range headers {
			r.headers.Set(k, v)
		}
	}
}

// Query appends a query parameter.
func Query(key, value string) ReqOption {
	return func(r *Request) { r.query.Set(key, value) }
}

// Queries appends several query parameters.
func Queries(params map[string]string) ReqOption {
	return func(r *Request) {
		for k, v := range params {
			r.query.Set(k, v)
		}
	}
}

// PathParam substitutes a path placeholder.
func PathParam(key, value string) ReqOption {
	return func(r *Request) { r.SetPathParam(key, value) }
}

// Cookie adds a cookie header value.
func Cookie(name, value string) ReqOption {
	return func(r *Request) { r.SetCookie(name, value) }
}

// CookieHeader sets an entire Cookie header (e.g. a session cookie string).
func CookieHeader(cookieString string) ReqOption {
	return func(r *Request) { r.headers.Set("Cookie", cookieString) }
}

// Body sets the request body (see Request.SetBody for encoding rules).
func Body(body any) ReqOption {
	return func(r *Request) { r.body = body }
}

// FormData sends form-urlencoded values.
func FormData(data map[string]string) ReqOption {
	return func(r *Request) { r.SetFormData(data) }
}

// BasicAuth sets HTTP basic authentication.
func BasicAuth(username, password string) ReqOption {
	return func(r *Request) { r.SetBasicAuth(username, password) }
}

// AuthToken sets a bearer token.
func AuthToken(token string) ReqOption {
	return func(r *Request) { r.SetAuthToken(token) }
}

// Result registers a pointer that is JSON-decoded from a 2xx response.
func Result(v any) ReqOption {
	return func(r *Request) { r.result = v }
}

// Timeout overrides the client timeout for this request.
func Timeout(d time.Duration) ReqOption {
	return func(r *Request) { r.SetTimeout(d) }
}

// Context sets the request context.
func Context(ctx context.Context) ReqOption {
	return func(r *Request) { r.SetContext(ctx) }
}
