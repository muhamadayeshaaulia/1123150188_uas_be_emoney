package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const identityToolkitSendOobCodeURL = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode"

// SendEmailVerificationLink calls the Firebase Identity Toolkit REST API to
// send a "verify email" link to the address tied to the given Firebase ID token.
func SendEmailVerificationLink(apiKey, idToken string) error {
	payload, err := json.Marshal(map[string]string{
		"requestType": "VERIFY_EMAIL",
		"idToken":     idToken,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("%s?key=%s", identityToolkitSendOobCodeURL, apiKey)
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("identitytoolkit sendOobCode failed (status %d): %s", resp.StatusCode, errBody.Error.Message)
	}

	return nil
}
