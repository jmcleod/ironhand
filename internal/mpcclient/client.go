package mpcclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderTimestamp = "X-Ironhand-MPC-Timestamp"
	HeaderSignature = "X-Ironhand-MPC-Signature"
)

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
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, signature(sharedKey, req.Method, req.URL.EscapedPath(), ts, body))
}

func VerifyRequest(r *http.Request, sharedKey []byte, maxSkew time.Duration) ([]byte, bool, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(sharedKey) == 0 {
		return body, true, nil
	}
	ts := r.Header.Get(HeaderTimestamp)
	got := r.Header.Get(HeaderSignature)
	if ts == "" || got == "" {
		return body, false, nil
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return body, false, nil
	}
	if time.Since(time.Unix(sec, 0)) > maxSkew || time.Until(time.Unix(sec, 0)) > maxSkew {
		return body, false, nil
	}
	want := signature(sharedKey, r.Method, r.URL.EscapedPath(), ts, body)
	return body, hmac.Equal([]byte(got), []byte(want)), nil
}

func signature(sharedKey []byte, method, path, ts string, body []byte) string {
	mac := hmac.New(sha256.New, sharedKey)
	mac.Write([]byte(method))
	mac.Write([]byte("\n"))
	mac.Write([]byte(path))
	mac.Write([]byte("\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
