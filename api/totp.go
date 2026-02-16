package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jmcleod/ironhand/internal/util"
)

const (
	totpSecretBytes = 20
	totpDigits      = 6
	totpPeriod      = 30
	totpWindow      = 1
	totpIssuer      = "Ironhand"
	totpSetupTTL    = 10 * time.Minute
)

func generateTOTPSecret() (string, error) {
	raw, err := util.RandomBytes(totpSecretBytes)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func normalizeTOTPCode(code string) string {
	return strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
}

func validTOTPCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func verifyTOTPCode(secret, code string, now time.Time) bool {
	code = normalizeTOTPCode(code)
	if !validTOTPCode(code) {
		return false
	}
	for i := -totpWindow; i <= totpWindow; i++ {
		at := now.Add(time.Duration(i*totpPeriod) * time.Second)
		expected, err := totpCodeAt(secret, at)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpCodeAt(secret string, at time.Time) (string, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}

	counter := uint64(at.Unix() / totpPeriod)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, decoded)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	otp := binCode % 1000000
	return fmt.Sprintf("%06d", otp), nil
}

func otpAuthURL(secret, accountLabel string) string {
	label := url.PathEscape(totpIssuer + ":" + accountLabel)
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", totpIssuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", strconv.Itoa(totpDigits))
	values.Set("period", strconv.Itoa(totpPeriod))
	return "otpauth://totp/" + label + "?" + values.Encode()
}
