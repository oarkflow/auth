//go:build js && wasm
// +build js,wasm

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"syscall/js"
	"time"
)

const (
	sessionTTL        = 10 * time.Minute
	maxPayloadBytes   = 1 << 20 // 1MB cap for outbound bodies
	maxResponseBytes  = 1 << 20 // 1MB cap for inbound payloads
	sessionHeaderName = "X-Session-ID"
)

type stringError string

func (e stringError) Error() string {
	return string(e)
}

var client *SecureClient

// =========================
// Main
// =========================
func main() {
	js.Global().Set("initClient", js.FuncOf(func(this js.Value, args []js.Value) any {
		baseURL := ""
		if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
			baseURL = args[0].String()
		}
		if baseURL == "" {
			// Use current origin as default
			baseURL = js.Global().Get("location").Get("origin").String()
		}
		client = NewSecureClient(baseURL)

		// Expose setSession function
		js.Global().Set("setSession", js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) < 4 {
				js.Global().Get("console").Call("log", "setSession requires sessionID, userID, sessionKeyB64, hmacKeyB64")
				return nil
			}
			sessionID := args[0].String()
			userID := args[1].String()
			sessionKeyB64 := args[2].String()
			hmacKeyB64 := args[3].String()
			SetSessionFromJS(client, sessionID, userID, sessionKeyB64, hmacKeyB64)
			return nil
		}))
		js.Global().Set("clearSession", js.FuncOf(func(this js.Value, args []js.Value) any {
			if client != nil {
				client.ClearSession()
			}
			return nil
		}))
		js.Global().Set("secureFetch", js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) < 1 {
				return js.Global().Get("Promise").Call("reject", "secureFetch requires a URL")
			}

			endpoint := args[0].String()
			opts := map[string]any{}
			if len(args) > 1 && !args[1].IsNull() && !args[1].IsUndefined() {
				// Convert JS object to Go map
				jsOpts := args[1]
				opts = convertJSObjectToMap(jsOpts)
			}

			return client.SecureFetch(endpoint, opts)
		}))

		return nil
	}))

	// Keep main alive so event handlers work
	select {}
}

type GenericRequest struct {
	Action    string         `json:"action"`
	Body      map[string]any `json:"body,omitempty"`
	Timestamp int64          `json:"timestamp"` // Unix timestamp for replay protection
	Nonce     string         `json:"nonce"`     // Unique nonce to prevent replay attacks
}

type GenericResponse struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

type SecureClient struct {
	BaseURL    string
	SessionID  string
	UserID     string
	SessionKey []byte
	HMACKey    []byte
	HttpClient js.Value
	sessionExp time.Time
	// New fields for enhanced functionality
	Timeout    time.Duration // Request timeout
	MaxRetries int           // Maximum retry attempts
	// Rate limiting
	requestTimes []time.Time
	maxRequests  int
	window       time.Duration
	// Security patterns
	DangerousPatterns []string
}

// SetSessionFromJS sets the session from JavaScript with base64 encoded keys
func SetSessionFromJS(client *SecureClient, sessionID, userID, sessionKeyB64, hmacKeyB64 string) {
	sessionKey, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		js.Global().Get("console").Call("error", "SecureClient sessionKey decode failed:", err.Error())
		return
	}
	defer zeroBytes(sessionKey)
	hmacKey, err := base64.StdEncoding.DecodeString(hmacKeyB64)
	if err != nil {
		js.Global().Get("console").Call("error", "SecureClient hmacKey decode failed:", err.Error())
		return
	}
	defer zeroBytes(hmacKey)
	if client == nil {
		js.Global().Get("console").Call("error", "SecureClient not initialized")
		return
	}
	if err := client.SetSession(sessionID, userID, sessionKey, hmacKey); err != nil {
		js.Global().Get("console").Call("error", "SecureClient set session failed:", err.Error())
	}
}

func NewSecureClient(baseURL string) *SecureClient {
	c := &SecureClient{
		BaseURL:           baseURL,
		HttpClient:        js.Global().Get("fetch"),
		Timeout:           30 * time.Second, // Default 30s timeout
		MaxRetries:        1,                // Default 1 retry
		maxRequests:       60,               // 60 requests per minute
		window:            time.Minute,
		requestTimes:      make([]time.Time, 0),
		DangerousPatterns: []string{"<script", "<iframe", "javascript:"},
	}
	return c
}

// SetSession sets the session credentials for secure communication
func (c *SecureClient) SetSession(sessionID, userID string, sessionKey, hmacKey []byte) error {
	if c == nil {
		return stringError("client not initialized")
	}
	sessionID = strings.TrimSpace(sessionID)
	userID = strings.TrimSpace(userID)
	if sessionID == "" {
		return stringError("sessionID cannot be empty")
	}
	switch len(sessionKey) {
	case 16, 24, 32:
	default:
		return stringError("invalid session key length")
	}
	if len(hmacKey) < sha256.Size {
		return stringError("HMAC key too short")
	}
	c.ClearSession()
	c.SessionID = sessionID
	c.UserID = userID
	c.SessionKey = append([]byte(nil), sessionKey...)
	c.HMACKey = append([]byte(nil), hmacKey...)
	c.sessionExp = time.Now().Add(sessionTTL)
	return nil
}

// ClearSession securely wipes the current session material.
func (c *SecureClient) ClearSession() {
	if c == nil {
		return
	}
	if len(c.SessionKey) > 0 {
		zeroBytes(c.SessionKey)
	}
	if len(c.HMACKey) > 0 {
		zeroBytes(c.HMACKey)
	}
	c.SessionID = ""
	c.UserID = ""
	c.SessionKey = nil
	c.HMACKey = nil
	c.sessionExp = time.Time{}
	c.requestTimes = nil
}

func encryptAES(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, stringError("failed to prepare cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, stringError("failed to create GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, stringError("failed to read nonce")
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, len(nonce)+len(sealed))
	copy(out, nonce)
	copy(out[len(nonce):], sealed)
	return out, nil
}

func decryptAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, stringError("failed to prepare cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, stringError("failed to create GCM")
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, stringError("ciphertext too short")
	}
	plain, err := gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return nil, stringError("decryption failed")
	}
	return plain, nil
}

func computeHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyHMAC(data, sig, key []byte) bool {
	return hmac.Equal(sig, computeHMAC(data, key))
}

func bytesToUint8Array(b []byte) js.Value {
	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	return u8
}

func uint8ArrayToBytes(u8 js.Value) []byte {
	b := make([]byte, u8.Get("byteLength").Int())
	js.CopyBytesToGo(b, u8)
	return b
}

func convertJSObjectToMap(obj js.Value) map[string]any {
	result := make(map[string]any)
	keys := js.Global().Get("Object").Call("keys", obj)
	for i := 0; i < keys.Length(); i++ {
		key := keys.Index(i).String()
		val := obj.Get(key)
		switch val.Type() {
		case js.TypeUndefined:
			result[key] = nil
		case js.TypeNull:
			result[key] = nil
		case js.TypeBoolean:
			result[key] = val.Bool()
		case js.TypeNumber:
			result[key] = val.Float()
		case js.TypeString:
			result[key] = val.String()
		case js.TypeSymbol:
			// Symbols can be converted to string representation
			result[key] = val.Call("toString").String()
		case js.TypeObject:
			// Handle nested objects or arrays
			if val.Get("constructor").Get("name").String() == "Array" {
				// Handle arrays
				arr := make([]any, val.Length())
				for j := 0; j < val.Length(); j++ {
					arrVal := val.Index(j)
					switch arrVal.Type() {
					case js.TypeUndefined:
						arr[j] = nil
					case js.TypeNull:
						arr[j] = nil
					case js.TypeBoolean:
						arr[j] = arrVal.Bool()
					case js.TypeNumber:
						arr[j] = arrVal.Float()
					case js.TypeString:
						arr[j] = arrVal.String()
					case js.TypeSymbol:
						arr[j] = arrVal.Call("toString").String()
					case js.TypeObject:
						if arrVal.Get("constructor").Get("name").String() == "Array" {
							// Nested array, simplify to nil for now
							arr[j] = nil
						} else {
							arr[j] = convertJSObjectToMap(arrVal)
						}
					case js.TypeFunction:
						arr[j] = nil // Skip functions
					default:
						arr[j] = nil
					}
				}
				result[key] = arr
			} else {
				// Handle nested objects
				result[key] = convertJSObjectToMap(val)
			}
		case js.TypeFunction:
			result[key] = nil // Skip functions in map
		default:
			result[key] = nil
		}
	}
	return result
}

func (c *SecureClient) SecureFetch(endpoint string, opts map[string]any) js.Value {
	if c == nil {
		return js.Global().Get("Promise").Call("reject", "SecureClient not initialized")
	}

	if opts == nil {
		opts = make(map[string]any)
	}

	if err := c.validateRequest(endpoint, opts); err != nil {
		return js.Global().Get("Promise").Call("reject", err.Error())
	}

	timeout := c.Timeout
	if t, ok := opts["timeout"]; ok && t != nil {
		if timeoutMs, ok := t.(float64); ok {
			timeout = time.Duration(timeoutMs) * time.Millisecond
		}
	}
	maxRetries := c.MaxRetries
	if mr, ok := opts["maxRetries"]; ok && mr != nil {
		if retries, ok := mr.(float64); ok {
			maxRetries = int(retries)
		}
	}

	extraHeaders := extractHeaderOverrides(opts)

	if params, ok := opts["params"]; ok && params != nil {
		if paramsMap, ok := params.(map[string]any); ok {
			queryParts := make([]string, 0, len(paramsMap))
			for k, v := range paramsMap {
				key := strings.TrimSpace(k)
				if key == "" {
					continue
				}
				queryParts = append(queryParts, url.QueryEscape(key)+"="+url.QueryEscape(fmt.Sprintf("%v", v)))
			}
			if len(queryParts) > 0 {
				queryStr := strings.Join(queryParts, "&")
				if strings.Contains(endpoint, "?") {
					endpoint += "&" + queryStr
				} else {
					endpoint += "?" + queryStr
				}
			}
		}
	}

	var payload map[string]any
	if body, ok := opts["body"]; ok && body != nil {
		switch b := body.(type) {
		case string:
			if containsDangerousPattern(b, c.DangerousPatterns) {
				return js.Global().Get("Promise").Call("reject", "Request body contains potentially dangerous content")
			}
			payload = parseBodyString(b)
		case map[string]any:
			payload = b
		case []any:
			payload = map[string]any{"items": b}
		default:
			// Attempt to serialize unknown body types
			if marshaled, err := json.Marshal(b); err == nil {
				payload = parseBodyString(string(marshaled))
			}
		}
	}

	action := deriveAction(endpoint, opts)

	promiseConstructor := js.Global().Get("Promise")
	executor := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]

		c.Call(endpoint, action, payload, timeout, maxRetries, extraHeaders, func(resp *GenericResponse, err error) {
			if err != nil {
				errorResp := map[string]any{
					"ok":         false,
					"status":     500,
					"statusText": err.Error(),
					"headers": map[string]any{
						"get": js.FuncOf(func(this js.Value, args []js.Value) any {
							return "text/plain"
						}),
					},
					"text": js.FuncOf(func(this js.Value, args []js.Value) any {
						return err.Error()
					}),
					"json": js.FuncOf(func(this js.Value, args []js.Value) any {
						return map[string]any{"error": err.Error()}
					}),
				}
				reject.Invoke(errorResp)
				return
			}

			respData, marshalErr := json.Marshal(resp.Data)
			if marshalErr != nil {
				reject.Invoke("failed to serialize response payload")
				return
			}
			successResp := map[string]any{
				"ok":         true,
				"status":     200,
				"statusText": "OK",
				"headers": map[string]any{
					"get": js.FuncOf(func(this js.Value, args []js.Value) any {
						headerName := args[0].String()
						if headerName == "content-type" {
							return "application/json"
						}
						return ""
					}),
				},
				"text": js.FuncOf(func(this js.Value, args []js.Value) any {
					return string(respData)
				}),
				"json": js.FuncOf(func(this js.Value, args []js.Value) any {
					var data any
					json.Unmarshal(respData, &data)
					return data
				}),
			}
			resolve.Invoke(successResp)
		})

		return nil
	})

	promise := promiseConstructor.New(executor)
	executor.Release()
	return promise
}
func (c *SecureClient) Call(url string, action string, payload map[string]any, timeout time.Duration, maxRetries int, extraHeaders map[string]string, cb func(*GenericResponse, error)) {
	if extraHeaders == nil {
		extraHeaders = make(map[string]string)
	}
	c.callWithRetry(url, action, payload, extraHeaders, cb, 0, timeout, maxRetries)
}

func (c *SecureClient) callWithRetry(url string, action string, payload map[string]any, extraHeaders map[string]string, cb func(*GenericResponse, error), attempt int, timeout time.Duration, maxRetries int) {
	if extraHeaders == nil {
		extraHeaders = make(map[string]string)
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	if c.SessionID == "" {
		cb(nil, stringError("not logged in"))
		return
	}
	if len(c.SessionKey) == 0 || len(c.HMACKey) == 0 {
		cb(nil, stringError("session keys unavailable"))
		return
	}
	if time.Now().After(c.sessionExp) {
		cb(nil, stringError("session expired"))
		return
	}
	if !c.checkRateLimit() {
		cb(nil, stringError("rate limit exceeded"))
		return
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		cb(nil, stringError("nonce generation failed"))
		return
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	req := GenericRequest{Action: action, Body: payload, Timestamp: time.Now().UTC().Unix(), Nonce: nonce}
	originalData, err := json.Marshal(req)
	if err != nil {
		cb(nil, stringError("request marshal failed"))
		return
	}
	if len(originalData) > maxPayloadBytes {
		cb(nil, stringError("request too large"))
		return
	}

	encryptedData, err := encryptAES(originalData, c.SessionKey)
	if err != nil {
		cb(nil, err)
		return
	}
	sig := computeHMAC(encryptedData, c.HMACKey)
	final := make([]byte, len(sig)+len(encryptedData))
	copy(final, sig)
	copy(final[len(sig):], encryptedData)
	if len(final) > maxPayloadBytes {
		cb(nil, stringError("request too large"))
		return
	}

	headers := map[string]any{
		"Content-Type":    "application/octet-stream",
		sessionHeaderName: c.SessionID,
		"Accept-Encoding": "gzip, br",
		"Content-Length":  fmt.Sprintf("%d", len(final)),
	}
	for k, v := range extraHeaders {
		lk := strings.ToLower(k)
		switch lk {
		case strings.ToLower(sessionHeaderName), "content-type", "content-length":
			continue
		default:
			if v != "" {
				headers[k] = v
			}
		}
	}
	opts := map[string]any{
		"method":  "POST",
		"body":    bytesToUint8Array(final),
		"headers": headers,
	}

	abortController := js.Global().Get("AbortController").New()
	signal := abortController.Get("signal")
	opts["signal"] = signal

	timerActive := false
	var timeoutFunc js.Func
	var timerID js.Value
	if timeout > 0 {
		timerActive = true
		timeoutFunc = js.FuncOf(func(this js.Value, args []js.Value) any {
			if !timerActive {
				return nil
			}
			timerActive = false
			timeoutFunc.Release()
			abortController.Call("abort")
			return nil
		})
		timerID = js.Global().Call("setTimeout", timeoutFunc, int(timeout.Milliseconds()))
	}

	resolvedURL := c.resolveURL(url)
	promise := c.HttpClient.Invoke(resolvedURL, opts)

	var thenFunc js.Func
	thenFunc = js.FuncOf(func(this js.Value, args []js.Value) any {
		defer thenFunc.Release()
		if timerActive {
			timerActive = false
			js.Global().Call("clearTimeout", timerID)
			timeoutFunc.Release()
		}
		resp := args[0]
		contentType := resp.Get("headers").Call("get", "content-type").String()
		if contentType != "application/octet-stream" {
			var textThen js.Func
			textThen = js.FuncOf(func(this js.Value, args []js.Value) any {
				defer textThen.Release()
				errorText := args[0].String()
				c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("server error: "+errorText))
				return nil
			})
			var textCatch js.Func
			textCatch = js.FuncOf(func(this js.Value, args []js.Value) any {
				defer textCatch.Release()
				c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("server returned non-octet-stream"))
				return nil
			})
			resp.Call("text").Call("then", textThen).Call("catch", textCatch)
			return nil
		}

		var bufferThen js.Func
		bufferThen = js.FuncOf(func(this js.Value, args []js.Value) any {
			defer bufferThen.Release()
			respBytes := uint8ArrayToBytes(js.Global().Get("Uint8Array").New(args[0]))
			if len(respBytes) < sha256.Size {
				c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("response too short"))
				return nil
			}
			respSig := respBytes[:sha256.Size]
			respData := respBytes[sha256.Size:]
			if !verifyHMAC(respData, respSig, c.HMACKey) {
				c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("HMAC verification failed"))
				return nil
			}
			plain, err := decryptAES(respData, c.SessionKey)
			if err != nil {
				c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("decryption failed"))
				return nil
			}
			if len(plain) > maxResponseBytes {
				c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("response too large"))
				return nil
			}
			var out GenericResponse
			if err := json.Unmarshal(plain, &out); err != nil {
				c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("JSON unmarshal failed"))
				return nil
			}
			c.refreshSessionExpiry()
			cb(&out, nil)
			return nil
		})
		var bufferCatch js.Func
		bufferCatch = js.FuncOf(func(this js.Value, args []js.Value) any {
			defer bufferCatch.Release()
			c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("failed to read response buffer"))
			return nil
		})
		resp.Call("arrayBuffer").Call("then", bufferThen).Call("catch", bufferCatch)
		return nil
	})
	promise.Call("then", thenFunc)

	var catchFunc js.Func
	catchFunc = js.FuncOf(func(this js.Value, args []js.Value) any {
		defer catchFunc.Release()
		if timerActive {
			timerActive = false
			js.Global().Call("clearTimeout", timerID)
			timeoutFunc.Release()
		}
		errVal := args[0]
		if errVal.Truthy() && errVal.Get("name").String() == "AbortError" {
			c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("request timeout"))
			return nil
		}
		c.handleRetry(url, action, payload, extraHeaders, cb, attempt, timeout, maxRetries, stringError("fetch error: "+errVal.String()))
		return nil
	})
	promise.Call("catch", catchFunc)
}

func (c *SecureClient) checkRateLimit() bool {
	now := time.Now()
	// Remove old requests outside the window
	validTimes := make([]time.Time, 0)
	for _, t := range c.requestTimes {
		if now.Sub(t) < c.window {
			validTimes = append(validTimes, t)
		}
	}
	c.requestTimes = validTimes

	if len(c.requestTimes) >= c.maxRequests {
		return false
	}

	c.requestTimes = append(c.requestTimes, now)
	return true
}

func (c *SecureClient) validateRequest(url string, opts map[string]any) error {
	if url == "" {
		return stringError("URL cannot be empty")
	}
	// Basic URL validation
	if len(url) > 2048 {
		return stringError("URL too long")
	}
	// Check for potentially dangerous characters
	dangerousChars := []string{"<", ">", "\"", "'", "javascript:", "data:"}
	for _, char := range dangerousChars {
		if strings.Contains(url, char) {
			return stringError("Invalid characters in URL")
		}
	}
	// Validate request body size
	if body, ok := opts["body"]; ok && body != nil {
		if bodyStr, ok := body.(string); ok {
			if len(bodyStr) > maxPayloadBytes {
				return stringError("request body too large")
			}
		}
	}
	return nil
}

func (c *SecureClient) handleRetry(url string, action string, payload map[string]any, extraHeaders map[string]string, cb func(*GenericResponse, error), attempt int, timeout time.Duration, maxRetries int, err error) {
	js.Global().Get("console").Call("warn", "SecureClient attempt", attempt+1, "failed:", err.Error())
	if isSessionInvalidError(err.Error()) {
		c.ClearSession()
		cb(nil, err)
		return
	}
	if attempt >= maxRetries {
		js.Global().Get("console").Call("error", "SecureClient max retries exceeded for", action)
		cb(nil, err)
		return
	}
	delay := retryDelay(attempt)
	var retryFunc js.Func
	retryFunc = js.FuncOf(func(this js.Value, args []js.Value) any {
		defer retryFunc.Release()
		c.callWithRetry(url, action, payload, extraHeaders, cb, attempt+1, timeout, maxRetries)
		return nil
	})
	js.Global().Call("setTimeout", retryFunc, int(delay.Milliseconds()))
}

func retryDelay(attempt int) time.Duration {
	base := 150 * time.Millisecond
	max := 2 * time.Second
	multiplier := time.Duration(1)
	if attempt > 0 {
		shift := attempt
		if shift > 4 {
			shift = 4
		}
		multiplier = 1 << shift
	}
	delay := base * multiplier
	if delay > max {
		delay = max
	}
	jitter := randomJitter(delay / 3)
	return delay + jitter
}

func randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return max / 2
	}
	val := binary.BigEndian.Uint64(buf[:])
	return time.Duration(val % uint64(max))
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func containsDangerousPattern(input string, patterns []string) bool {
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func parseBodyString(body string) map[string]any {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
		return normalizePayload(parsed)
	}
	return map[string]any{"data": trimmed}
}

func normalizePayload(value any) map[string]any {
	if value == nil {
		return nil
	}
	if m, ok := value.(map[string]any); ok {
		return m
	}
	if m, ok := value.(map[string]interface{}); ok {
		conv := make(map[string]any, len(m))
		for key, val := range m {
			conv[key] = val
		}
		return conv
	}
	if arr, ok := value.([]any); ok {
		return map[string]any{"items": arr}
	}
	if arr, ok := value.([]interface{}); ok {
		conv := make([]any, len(arr))
		copy(conv, arr)
		return map[string]any{"items": conv}
	}
	if str, ok := value.(string); ok {
		return map[string]any{"data": str}
	}
	return map[string]any{"value": value}
}

func deriveAction(endpoint string, opts map[string]any) string {
	if opts != nil {
		if raw, ok := opts["action"]; ok {
			if action, ok := raw.(string); ok {
				if trimmed := strings.TrimSpace(action); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	clean := endpoint
	if idx := strings.Index(clean, "?"); idx >= 0 {
		clean = clean[:idx]
	}
	clean = strings.Trim(clean, "/")
	if clean == "" {
		return "root"
	}
	parts := strings.Split(clean, "/")
	action := parts[len(parts)-1]
	if action == "" {
		return "root"
	}
	return action
}

func extractHeaderOverrides(opts map[string]any) map[string]string {
	overrides := make(map[string]string)
	if opts == nil {
		return overrides
	}
	raw, ok := opts["headers"]
	if !ok || raw == nil {
		return overrides
	}
	if headerMap, ok := raw.(map[string]any); ok {
		for key, val := range headerMap {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" || val == nil {
				continue
			}
			switch v := val.(type) {
			case string:
				overrides[trimmedKey] = v
			case fmt.Stringer:
				overrides[trimmedKey] = v.String()
			default:
				overrides[trimmedKey] = fmt.Sprintf("%v", v)
			}
		}
	}
	return overrides
}

func (c *SecureClient) resolveURL(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if strings.HasPrefix(endpoint, "/") {
		return base + endpoint
	}
	return base + "/" + endpoint
}

func (c *SecureClient) refreshSessionExpiry() {
	if c == nil {
		return
	}
	c.sessionExp = time.Now().Add(sessionTTL)
}

func isSessionInvalidError(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "invalid session") || strings.Contains(lower, "session expired") || strings.Contains(lower, "not logged in")
}
