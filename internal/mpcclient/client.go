package mpcclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	HeaderTimestamp = "X-Ironhand-MPC-Timestamp"
	HeaderNonce     = "X-Ironhand-MPC-Nonce"
	HeaderBodyHash  = "X-Ironhand-MPC-Body-SHA256"
	HeaderSignature = "X-Ironhand-MPC-Signature"
)

type ReplayCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	maxSkew time.Duration
}

func NewReplayCache(maxSkew time.Duration) *ReplayCache {
	return &ReplayCache{seen: make(map[string]time.Time), maxSkew: maxSkew}
}

func (c *ReplayCache) Mark(nonce string, now time.Time) bool {
	if c == nil || nonce == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for value, expiry := range c.seen {
		if !expiry.After(now) {
			delete(c.seen, value)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	c.seen[nonce] = now.Add(2 * c.maxSkew)
	return true
}

type Client struct {
	httpClient *http.Client
	sharedKey  []byte
}

func New(sharedKey []byte, tlsConfig *tls.Config) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second, Transport: transport},
		sharedKey:  append([]byte(nil), sharedKey...),
	}
}

func (c *Client) GetJSON(url string, out any) error {
	return c.doJSON(http.MethodGet, url, nil, out)
}

func (c *Client) PostJSON(url string, in any, out any) error {
	return c.doJSON(http.MethodPost, url, in, out)
}

func (c *Client) doJSON(method, url string, in any, out any) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, strings.TrimRight(url, "/"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	SignRequest(req, c.sharedKey, body, time.Now())
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func SignRequest(req *http.Request, sharedKey []byte, body []byte, now time.Time) {
	if len(sharedKey) == 0 {
		return
	}
	ts := strconv.FormatInt(now.UTC().Unix(), 10)
	nonce := randomNonce()
	bodyHash := hashBody(body)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodyHash, bodyHash)
	req.Header.Set(HeaderSignature, signature(sharedKey, req.Method, canonicalScheme(req), canonicalHost(req), req.URL.EscapedPath(), req.URL.RawQuery, ts, nonce, bodyHash))
}

func VerifyRequest(r *http.Request, sharedKey []byte, maxSkew time.Duration) ([]byte, bool, error) {
	return VerifyRequestWithReplay(r, sharedKey, maxSkew, nil)
}

func VerifyRequestWithReplay(r *http.Request, sharedKey []byte, maxSkew time.Duration, replay *ReplayCache) ([]byte, bool, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(sharedKey) == 0 {
		return body, isLoopbackRequest(r), nil
	}
	ts := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	bodyHash := r.Header.Get(HeaderBodyHash)
	got := r.Header.Get(HeaderSignature)
	if ts == "" || nonce == "" || bodyHash == "" || got == "" {
		return body, false, nil
	}
	if !hmac.Equal([]byte(bodyHash), []byte(hashBody(body))) {
		return body, false, nil
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return body, false, nil
	}
	now := time.Now()
	if now.Sub(time.Unix(sec, 0)) > maxSkew || time.Until(time.Unix(sec, 0)) > maxSkew {
		return body, false, nil
	}
	want := signature(sharedKey, r.Method, canonicalScheme(r), canonicalHost(r), r.URL.EscapedPath(), r.URL.RawQuery, ts, nonce, bodyHash)
	if !hmac.Equal([]byte(got), []byte(want)) {
		return body, false, nil
	}
	if !replay.Mark(nonce, now) {
		return body, false, nil
	}
	return body, true, nil
}

func signature(sharedKey []byte, method, scheme, host, path, query, ts, nonce, bodyHash string) string {
	mac := hmac.New(sha256.New, sharedKey)
	mac.Write([]byte(method))
	mac.Write([]byte("\n"))
	mac.Write([]byte(scheme))
	mac.Write([]byte("\n"))
	mac.Write([]byte(host))
	mac.Write([]byte("\n"))
	mac.Write([]byte(path))
	mac.Write([]byte("\n"))
	mac.Write([]byte(query))
	mac.Write([]byte("\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write([]byte(bodyHash))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func randomNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func canonicalScheme(r *http.Request) string {
	if r.URL.Scheme != "" {
		return strings.ToLower(r.URL.Scheme)
	}
	if r.TLS != nil {
		return "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		return strings.ToLower(strings.Split(forwarded, ",")[0])
	}
	return "http"
}

func canonicalHost(r *http.Request) string {
	if r.URL.Host != "" {
		return strings.ToLower(r.URL.Host)
	}
	return strings.ToLower(r.Host)
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
