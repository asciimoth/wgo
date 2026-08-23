package amnezia

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ProxyCache stores the encrypted S3 object, matching the official client's
// cache semantics. Implementations must be safe for concurrent use and treat
// data as untrusted input.
type ProxyCache interface {
	Load(ctx context.Context, key string) ([]byte, bool, error)
	Store(ctx context.Context, key string, encrypted []byte) error
}

// MemoryProxyCache is a process-local, concurrency-safe ProxyCache.
type MemoryProxyCache struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryProxyCache creates an empty process-local proxy cache.
func NewMemoryProxyCache() *MemoryProxyCache { return &MemoryProxyCache{data: make(map[string][]byte)} }

func (c *MemoryProxyCache) Load(_ context.Context, key string) ([]byte, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.data[key]
	return append([]byte(nil), value...), ok, nil
}

func (c *MemoryProxyCache) Store(_ context.Context, key string, encrypted []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = append([]byte(nil), encrypted...)
	return nil
}

func proxyCacheKey(serviceType, country string) string {
	return "service_" + serviceType + "_country_" + country
}

func proxyStorageNames(serviceType, country string) []string {
	var names []string
	if serviceType != "" {
		name := "endpoints-" + serviceType + "-" + country
		names = append(names, base64.RawURLEncoding.EncodeToString([]byte(name))+".json")
	}
	return append(names, "endpoints.json")
}

func (c *Client) discoverProxyURLs(ctx context.Context, serviceType, country string) []string {
	cacheKey := proxyCacheKey(serviceType, country)
	var dynamic []string
	if !c.disableS3 {
		primary := cloneStrings(c.primaryS3)
		fallback := cloneStrings(c.fallbackS3)
		c.shuffle(primary)
		c.shuffle(fallback)
		for _, bases := range [][]string{primary, fallback} {
			for _, name := range proxyStorageNames(serviceType, country) {
				for _, base := range bases {
					encrypted, err := c.fetchProxyObject(ctx, base+name)
					if err != nil {
						continue
					}
					urls, err := decryptProxyList(encrypted, c.publicKeyPEM)
					if err != nil || len(urls) == 0 {
						continue
					}
					dynamic = urls
					_ = c.proxyCache.Store(ctx, cacheKey, encrypted)
					break
				}
				if len(dynamic) > 0 {
					break
				}
			}
			if len(dynamic) > 0 {
				break
			}
		}
	}
	if len(dynamic) == 0 {
		if encrypted, ok, err := c.proxyCache.Load(ctx, cacheKey); err == nil && ok {
			dynamic, _ = decryptProxyList(encrypted, c.publicKeyPEM)
		}
	}
	return dedupeURLs(append(dynamic, c.staticProxies...))
}

func (c *Client) fetchProxyObject(ctx context.Context, target string) ([]byte, error) {
	requestContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("storage HTTP status %d", resp.StatusCode)
	}
	return readLimited(resp.Body, c.maxResponseBytes)
}

func decryptProxyList(encryptedBase64, exactPublicPEM []byte) ([]string, error) {
	encoded := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, string(encryptedBase64))
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		ciphertext, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("proxy-list base64: %w", err)
	}
	digest := sha512.Sum512(exactPublicPEM)
	plain, err := decryptAES256CBC(ciphertext, digest[:32], digest[32:48])
	if err != nil {
		return nil, fmt.Errorf("proxy-list AES: %w", err)
	}
	var raw []string
	if err := json.Unmarshal(plain, &raw); err != nil {
		return nil, fmt.Errorf("proxy-list JSON: %w", err)
	}
	return normalizeURLList(raw)
}

func dedupeURLs(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, value := range urls {
		normalized, err := normalizeBaseURL(value)
		if err != nil {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func (c *Client) shuffle(values []string) {
	_ = c.withRandom(func(random io.Reader) error {
		var raw [8]byte
		for i := len(values) - 1; i > 0; i-- {
			if _, err := io.ReadFull(random, raw[:]); err != nil {
				return err
			}
			j := int(binary.LittleEndian.Uint64(raw[:]) % uint64(i+1))
			values[i], values[j] = values[j], values[i]
		}
		return nil
	})
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	limited := &io.LimitedReader{R: reader, N: limit + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("response exceeds size limit")
	}
	return data, nil
}
