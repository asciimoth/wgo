package amnezia

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type gatewayReply struct {
	body       []byte
	object     map[string]any
	httpStatus int
}

type gatewayAttempt struct {
	reply      *gatewayReply
	err        error
	useAnother bool
}

func (c *Client) postGateway(ctx context.Context, endpoint string, payload map[string]any, serviceType, country string) (*gatewayReply, error) {
	requestID, err := c.newRequestID()
	if err != nil {
		return nil, err
	}
	var envelope *encryptedEnvelope
	if err := c.withRandom(func(randomReader io.Reader) error {
		var prepareErr error
		envelope, prepareErr = prepareEnvelope(randomReader, c.publicKey, payload, requestID)
		return prepareErr
	}); err != nil {
		return nil, &ProtocolError{Op: "prepare gateway request", Err: err}
	}

	direct := c.doGatewayPost(ctx, c.gatewayURL, endpoint, envelope)
	if !direct.useAnother {
		return finishGatewayAttempt(direct)
	}
	if isTLSError(direct.err) {
		return nil, direct.err
	}

	proxies := c.discoverProxyURLs(ctx, serviceType, country)
	if preferred := c.getPreferredProxy(); preferred != "" {
		proxies = dedupeURLs(append([]string{preferred}, proxies...))
	}
	c.shuffle(proxies)
	if preferred := c.getPreferredProxy(); preferred != "" {
		proxies = append([]string{preferred}, removeURL(proxies, preferred)...)
	}

	last := direct
	for _, proxy := range proxies {
		if err := c.checkProxyHealth(ctx, proxy); err != nil {
			continue
		}
		attempt := c.doGatewayPost(ctx, proxy, endpoint, envelope)
		last = attempt
		if !attempt.useAnother {
			c.setPreferredProxy(proxy)
			return finishGatewayAttempt(attempt)
		}
	}
	return finishGatewayAttempt(last)
}

func finishGatewayAttempt(attempt gatewayAttempt) (*gatewayReply, error) {
	if attempt.err != nil {
		return attempt.reply, attempt.err
	}
	if attempt.reply == nil {
		return nil, errors.New("amnezia: gateway returned no response")
	}
	if apiErr := classifyAPIError(attempt.reply); apiErr != nil {
		return attempt.reply, apiErr
	}
	return attempt.reply, nil
}

func (c *Client) doGatewayPost(ctx context.Context, base, endpoint string, envelope *encryptedEnvelope) gatewayAttempt {
	target, err := endpointURL(base, endpoint)
	if err != nil {
		return gatewayAttempt{err: err, useAnother: false}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(envelope.body))
	if err != nil {
		return gatewayAttempt{err: err, useAnother: false}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Client-Request-ID", envelope.requestID)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return gatewayAttempt{err: fmt.Errorf("amnezia gateway POST: %w", err), useAnother: true}
	}
	defer func() { _ = resp.Body.Close() }()
	encrypted, err := readLimited(resp.Body, c.maxResponseBytes)
	if err != nil {
		return gatewayAttempt{err: err, useAnother: true}
	}
	plain, err := decryptAES256CBC(encrypted, envelope.key, envelope.iv)
	if err != nil {
		// The official client runs domain-error classification against the raw
		// body when response decryption fails. Accept plaintext JSON only as an
		// error response; a plaintext success is never trusted as a profile.
		var rawObject map[string]any
		if json.Unmarshal(encrypted, &rawObject) == nil {
			status := objectInt(rawObject, "http_status")
			if status == 0 {
				status = resp.StatusCode
			}
			if status >= 300 {
				reply := &gatewayReply{body: encrypted, object: rawObject, httpStatus: resp.StatusCode}
				return gatewayAttempt{reply: reply, useAnother: shouldUseAnotherGateway(reply)}
			}
		}
		return gatewayAttempt{err: &ProtocolError{Op: "decrypt gateway response", Err: err}, useAnother: true}
	}
	var object map[string]any
	if err := json.Unmarshal(plain, &object); err != nil {
		return gatewayAttempt{err: &ProtocolError{Op: "parse gateway response", Err: err}, useAnother: true}
	}
	reply := &gatewayReply{body: plain, object: object, httpStatus: resp.StatusCode}
	return gatewayAttempt{reply: reply, useAnother: shouldUseAnotherGateway(reply)}
}

func shouldUseAnotherGateway(reply *gatewayReply) bool {
	lower := strings.ToLower(string(reply.body))
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype html") {
		return true
	}
	status := objectInt(reply.object, "http_status")
	if status == 0 {
		status = reply.httpStatus
	}
	message := strings.TrimSpace(objectString(reply.object, "message"))
	switch status {
	case 408, 409, 402:
		return false
	case 404:
		known := []string{
			"no active configuration found for",
			"no non-revoked public key found for",
			"account not found.",
			"qr session not found",
			"session not found",
		}
		for _, pattern := range known {
			if strings.Contains(lower, pattern) {
				return false
			}
		}
		return true
	case 501:
		return !strings.Contains(lower, "client version update is required")
	case 422:
		return message != "Failed to retrieve subscription information. Is it activated?"
	}
	return reply.httpStatus >= 500
}

func classifyAPIError(reply *gatewayReply) error {
	status := objectInt(reply.object, "http_status")
	if status == 0 && reply.httpStatus >= 300 {
		status = reply.httpStatus
	}
	if status < 300 {
		return nil
	}
	message := strings.TrimSpace(objectString(reply.object, "message"))
	lower := strings.ToLower(message)
	code := ErrorConfigDownload
	switch status {
	case 429:
		code = ErrorRateLimited
	case 409:
		if strings.Contains(lower, "trial subscription already used") {
			code = ErrorTrialAlreadyUsed
		} else {
			code = ErrorConfigLimit
		}
	case 404:
		code = ErrorNotFound
	case 408:
		code = ErrorTimeout
	case 501:
		code = ErrorUpdateRequired
	case 422:
		if message == "Failed to retrieve subscription information. Is it activated?" {
			code = ErrorSubscriptionExpired
		}
	case 402:
		switch {
		case strings.Contains(lower, "refresh_captcha"):
			code = ErrorCaptchaRefresh
		case strings.Contains(lower, "invalid_captcha"):
			code = ErrorCaptchaInvalid
		case objectString(reply.object, "captcha_id") != "", objectString(reply.object, "captcha_image") != "",
			strings.Contains(lower, "rate_limit_exceeded"):
			code = ErrorCaptchaRequired
		default:
			code = ErrorSubscriptionInactive
		}
	}
	return &APIError{Code: code, HTTPStatus: status, Message: message}
}

func objectString(object map[string]any, key string) string {
	value, ok := object[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

func objectInt(object map[string]any, key string) int {
	switch value := object[key].(type) {
	case float64:
		return int(value)
	case json.Number:
		parsed, _ := value.Int64()
		return int(parsed)
	case int:
		return value
	default:
		return 0
	}
}

func (c *Client) newRequestID() (string, error) {
	var raw [16]byte
	err := c.withRandom(func(reader io.Reader) error {
		_, err := io.ReadFull(reader, raw[:])
		return err
	})
	if err != nil {
		return "", fmt.Errorf("amnezia: generate request UUID: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return formatUUID(raw), nil
}

func (c *Client) checkProxyHealth(ctx context.Context, proxy string) error {
	healthContext, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	target, err := endpointURL(proxy, "lmbd-health")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(healthContext, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("proxy health status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) getPreferredProxy() string {
	c.preferredMu.RLock()
	defer c.preferredMu.RUnlock()
	return c.preferredProxy
}

func (c *Client) setPreferredProxy(proxy string) {
	c.preferredMu.Lock()
	defer c.preferredMu.Unlock()
	c.preferredProxy = proxy
}

func removeURL(values []string, target string) []string {
	out := values[:0]
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && strings.Contains(strings.ToLower(opErr.Error()), "tls")
}
