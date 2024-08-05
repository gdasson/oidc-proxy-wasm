package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"

	"golang.org/x/crypto/chacha20poly1305"
)

// SigningKey represents the public keys used for ID token validation.
// Define the actual fields as per your requirement.
type SigningKey struct{}

// OpenIdConfig holds the configuration for the OpenID Connect Flow.
type OpenIdConfig struct {
	AuthEndpoint  url.URL      `json:"auth_endpoint"`
	TokenEndpoint url.URL      `json:"token_endpoint"`
	Issuer        string       `json:"issuer"`
	PublicKeys    []SigningKey `json:"public_keys"`
}

// PluginConfiguration holds the configuration for the plugin, loaded from the config file `envoy.yaml`.
type PluginConfiguration struct {
	ConfigEndpoint          url.URL          `json:"config_endpoint"`
	ReloadIntervalInH       uint64           `json:"reload_interval_in_h"`
	ExcludeHosts            []*regexp.Regexp `json:"exclude_hosts"`
	ExcludePaths            []*regexp.Regexp `json:"exclude_paths"`
	ExcludeUrls             []*regexp.Regexp `json:"exclude_urls"`
	AccessTokenHeaderName   *string          `json:"access_token_header_name"`
	AccessTokenHeaderPrefix *string          `json:"access_token_header_prefix"`
	IdTokenHeaderName       *string          `json:"id_token_header_name"`
	IdTokenHeaderPrefix     *string          `json:"id_token_header_prefix"`
	CookieName              string           `json:"cookie_name"`
	FilterPluginCookies     bool             `json:"filter_plugin_cookies"`
	CookieDuration          uint64           `json:"cookie_duration"`
	TokenValidation         bool             `json:"token_validation"`
	AesKey                  SecretAesKey     `json:"aes_key"`
	Authority               string           `json:"authority"`
	RedirectURI             url.URL          `json:"redirect_uri"`
	ClientID                string           `json:"client_id"`
	Scope                   string           `json:"scope"`
	Claims                  string           `json:"claims"`
	ClientSecret            SecretString     `json:"client_secret"`
	Audience                string           `json:"audience"`
}

// SecretAesKey wraps the AES key used for encryption and decryption.
type SecretAesKey struct {
	Cipher *chacha20poly1305.Cipher
}

// SecretString wraps a string that should be treated as a secret.
type SecretString struct {
	Value string
}

// UnmarshalJSON handles the deserialization of a base64 encoded 32-byte AES key.
func (s *SecretAesKey) UnmarshalJSON(data []byte) error {
	var base64Key string
	if err := json.Unmarshal(data, &base64Key); err != nil {
		return err
	}

	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return fmt.Errorf("failed to decode base64 AES key: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("invalid key length: got %d bytes, expected %d", len(key), chacha20poly1305.KeySize)
	}

	s.Cipher, err = chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	return nil
}

func main() {
	// Example usage or testing logic can go here...
}
