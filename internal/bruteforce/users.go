package bruteforce

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/lfgrillo83/joomhound/internal/http"
	"github.com/lfgrillo83/joomhound/internal/models"
)

type UserEnumerator struct {
	client  *http.Client
	threads int
}

func NewUserEnumerator(client *http.Client, threads int) *UserEnumerator {
	if threads <= 0 {
		threads = 10
	}
	return &UserEnumerator{
		client:  client,
		threads: threads,
	}
}

// EnumerateUsers attempts to discover valid usernames
func (ue *UserEnumerator) EnumerateUsers(targetURL string, usernames []string) []models.User {
	var users []models.User
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, ue.threads)

	for _, username := range usernames {
		wg.Add(1)
		go func(user string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			found := false
			var userID int

			// Try multiple enumeration methods
			if id, ok := ue.enumerateViaRegistration(targetURL, user); ok {
				found = true
				userID = id
			} else if id, ok := ue.enumerateViaAPI(targetURL, user); ok {
				found = true
				userID = id
			} else if id, ok := ue.enumerateViaErrorMessages(targetURL, user); ok {
				found = true
				userID = id
			}

			if found {
				mu.Lock()
				users = append(users, models.User{
					Username: user,
					ID:       userID,
					Found:    true,
				})
				mu.Unlock()
			}
		}(username)
	}

	wg.Wait()
	return users
}

// enumerateViaRegistration checks user existence via registration form
// Joomla exposes this at /index.php?option=com_user&view=registration
func (ue *UserEnumerator) enumerateViaRegistration(targetURL string, username string) (int, bool) {
	// Try validation endpoint
	registrationURL := targetURL + "/index.php?option=com_user&task=registration.validateUsername"

	data := url.Values{
		"username": {username},
	}.Encode()

	resp, err := ue.client.Post(
		registrationURL,
		[]byte(data),
		"application/x-www-form-urlencoded",
	)

	if err != nil || resp.StatusCode != 200 {
		return 0, false
	}

	content := resp.String()

	// Joomla returns JSON with validation errors
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(resp.Body, &jsonResp); err != nil {
		return 0, false
	}

	// If username is invalid format or exists, Joomla returns specific errors
	if message, ok := jsonResp["message"]; ok {
		msgStr := message.(string)
		// Check if username is taken (exists)
		if strings.Contains(msgStr, "already exists") {
			return 0, true // User exists
		}
	}

	return 0, false
}

// enumerateViaAPI attempts to enumerate via Joomla API
func (ue *UserEnumerator) enumerateViaAPI(targetURL string, username string) (int, bool) {
	apiURL := fmt.Sprintf("%s/api/index.php/v1/users?search=%s", targetURL, username)

	resp, err := ue.client.Get(apiURL)
	if err != nil || resp.StatusCode != 200 {
		return 0, false
	}

	var apiResp map[string]interface{}
	if err := json.Unmarshal(resp.Body, &apiResp); err != nil {
		return 0, false
	}

	// Check if users array exists and has results
	if data, ok := apiResp["data"].([]interface{}); ok && len(data) > 0 {
		if user, ok := data[0].(map[string]interface{}); ok {
			if id, ok := user["id"].(float64); ok {
				return int(id), true
			}
		}
	}

	return 0, false
}

// enumerateViaErrorMessages checks response differences for error messages
// Some Joomla versions leak user existence through error messages
func (ue *UserEnumerator) enumerateViaErrorMessages(targetURL string, username string) (int, bool) {
	// Try admin login with wrong password
	loginURL := targetURL + "/administrator/"

	data := url.Values{
		"username": {username},
		"passwd":   {"randomwrongpassword123"},
		"option":   {"com_login"},
		"task":     {"login"},
	}.Encode()

	resp, err := ue.client.Post(
		loginURL,
		[]byte(data),
		"application/x-www-form-urlencoded",
	)

	if err != nil {
		return 0, false
	}

	content := resp.String()

	// Different error messages indicate if user exists
	if strings.Contains(content, "Invalid username or password") ||
		strings.Contains(content, "Login unsuccessful") {
		// User might exist - check for more specific indicators
		if strings.Contains(content, "User does not exist") ||
		   strings.Contains(content, "user not found") {
			return 0, false
		}
		// Generic message might mean user exists
		return 0, true
	}

	if strings.Contains(content, "Authentication Failed") {
		return 0, true // User likely exists
	}

	return 0, false
}

// EnumerateViaJSONAPI is an alternative using Joomla's JSON API (if enabled)
func (ue *UserEnumerator) EnumerateViaJSONAPI(targetURL string, usernames []string) []models.User {
	var users []models.User

	for _, username := range usernames {
		if id, ok := ue.enumerateViaAPI(targetURL, username); ok {
			users = append(users, models.User{
				Username: username,
				ID:       id,
				Found:    true,
			})
		}
	}

	return users
}

// EnumerateViaProfilePages attempts to find user profile pages
func (ue *UserEnumerator) EnumerateViaProfilePages(targetURL string, startID int, maxID int) []models.User {
	var users []models.User
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, ue.threads)

	for id := startID; id <= maxID; id++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			profileURL := fmt.Sprintf(
				"%s/index.php?option=com_users&view=profile&id=%d",
				targetURL,
				userID,
			)

			resp, err := ue.client.Get(profileURL)
			if err == nil && resp.StatusCode == 200 {
				content := resp.String()
				// Try to extract username from profile
				re := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
				matches := re.FindStringSubmatch(content)

				if len(matches) > 1 && !strings.Contains(matches[1], "Error") {
					mu.Lock()
					users = append(users, models.User{
						Username: strings.TrimSpace(matches[1]),
						ID:       userID,
						Found:    true,
					})
					mu.Unlock()
				}
			}
		}(id)
	}

	wg.Wait()
	return users
}
