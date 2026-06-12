package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

// responseWriter wraps gin.ResponseWriter to capture the response body.
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// sensitiveKeys are masked in logged request bodies.
var sensitiveKeys = map[string]bool{
	"password":       true,
	"firebase_token": true,
	"access_token":   true,
	"otp_code":       true,
	"totp_code":      true,
	"secret":         true,
}

func maskBody(raw []byte) string {
	if len(raw) == 0 {
		return "-"
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		// Not JSON — truncate and return as-is
		//if len(raw) > 200 {
		//	return string(raw[:200]) + "...(truncated)"
		//}
		return string(raw)
	}
	//for k := range m {
	//	if sensitiveKeys[strings.ToLower(k)] {
	//		m[k] = "***"
	//	}
	//}
	out, _ := json.Marshal(m)
	return string(out)
}

func statusColor(code int) string {
	switch {
	case code >= 500:
		return "\033[31m" // red
	case code >= 400:
		return "\033[33m" // yellow
	case code >= 300:
		return "\033[36m" // cyan
	default:
		return "\033[32m" // green
	}
}

const reset = "\033[0m"

// Logger is a Gin middleware that logs each request and response.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		if raw := c.Request.URL.RawQuery; raw != "" {
			path = path + "?" + raw
		}

		// Read and restore request body
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Wrap response writer
		rw := &responseWriter{ResponseWriter: c.Writer, body: &bytes.Buffer{}}
		c.Writer = rw

		// Log incoming request
		userID, _ := c.Get("user_id")
		userStr := "-"
		if userID != nil && fmt.Sprintf("%v", userID) != "0" {
			userStr = fmt.Sprintf("%v", userID)
		}

		log.Printf("\n┌─ REQUEST ─────────────────────────────\n"+
			"│  %s %s\n"+
			"│  IP      : %s\n"+
			"│  User-ID : %s\n"+
			"│  Body    : %s\n"+
			"└────────────────────────────────────────",
			c.Request.Method, path,
			c.ClientIP(),
			userStr,
			maskBody(bodyBytes),
		)

		c.Next()

		// Log response
		duration := time.Since(start)
		status := rw.Status()
		color := statusColor(status)

		// Pretty-print response body (JSON if possible)
		respBody := rw.body.Bytes()
		var prettyResp string
		if len(respBody) > 0 {
			var out bytes.Buffer
			if err := json.Indent(&out, respBody, "│  ", "  "); err == nil {
				prettyResp = out.String()
			} else {
				prettyResp = string(respBody)
			}
			if len(prettyResp) > 1000 {
				prettyResp = prettyResp[:1000] + "\n│  ...(truncated)"
			}
		} else {
			prettyResp = "-"
		}

		log.Printf("\n└─ RESPONSE ─────────────────────────────\n"+
			"│  %s%d%s %s  [%s]\n"+
			"│  Body :\n"+
			"│  %s\n"+
			"└─────────────────────────────────────────",
			color, status, reset,
			path,
			duration.Round(time.Millisecond),
			prettyResp,
		)
	}
}
