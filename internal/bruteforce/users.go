package bruteforce

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/w41l3r/joomhound/internal/http"
	"github.com/w41l3r/joomhound/internal/models"
)

// UserEnumerator discovers valid Joomla usernames.
type UserEnumerator struct {
	client  *http.Client
	threads int

	// OnFound is called for each confirmed user.
	OnFound func(models.User)
	// OnMessage reports method availability and warnings.
	OnMessage func(string)
}

// NewUserEnumerator creates an enumerator.
func NewUserEnumerator(client *http.Client, threads int) *UserEnumerator {
	if threads <= 0 {
		threads = 10
	}
	return &UserEnumerator{client: client, threads: threads}
}

func (ue *UserEnumerator) logf(format string, args ...any) {
	if ue.OnMessage != nil {
		ue.OnMessage(fmt.Sprintf(format, args...))
	}
}

// EnumerateUsers checks candidate usernames through Joomla's public web
// services API when the target exposes it. It deliberately avoids registration
// submissions: those mutate server-side state on some Joomla versions and do
// not provide a reliable cross-version existence oracle.
func (ue *UserEnumerator) EnumerateUsers(ctx context.Context, targetURL string, usernames []string) ([]models.User, error) {
	base := NormalizeTarget(targetURL)

	if len(usernames) == 0 {
		return nil, nil
	}

	// Probe the API before spending the wordlist.
	apiUsable := ue.probeAPI(ctx, base)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !apiUsable {
		ue.logf("[-] no reliable user-enumeration vector available " +
			"(the public Joomla API is unavailable); skipping")
		return nil, nil
	}
	ue.logf("[+] user enumeration via public Joomla API is available")

	var (
		mu  sync.Mutex
		out []models.User
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, ue.threads)

	for _, name := range usernames {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		// Acquire before spawning: the old code launched one goroutine per
		// wordlist entry and only then blocked, so a large wordlist created
		// millions of goroutines at once.
		sem <- struct{}{}

		go func(username string) {
			defer wg.Done()
			defer func() { <-sem }()

			userID, found := ue.viaAPI(ctx, base, username)
			if !found {
				return
			}

			u := models.User{
				Username: username,
				ID:       userID,
				Found:    true,
				Method:   "public-api",
			}

			mu.Lock()
			out = append(out, u)
			mu.Unlock()

			if ue.OnFound != nil {
				ue.OnFound(u)
			}
		}(name)
	}

	wg.Wait()
	return out, ctx.Err()
}

// probeAPI checks whether the Joomla 4+ public web-services API answers
// unauthenticated user queries (it normally returns 401/403).
func (ue *UserEnumerator) probeAPI(ctx context.Context, base string) bool {
	resp, err := ue.client.Get(ctx, base+"/api/index.php/v1/users")
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return false
	}
	_, ok := payload["data"]
	return ok
}

// viaAPI looks a username up through the public API.
func (ue *UserEnumerator) viaAPI(ctx context.Context, base, username string) (int, bool) {
	endpoint := fmt.Sprintf("%s/api/index.php/v1/users?filter[search]=%s",
		base, url.QueryEscape(username))

	resp, err := ue.client.Get(ctx, endpoint)
	if err != nil || resp.StatusCode != 200 {
		return 0, false
	}

	var payload struct {
		Data []struct {
			ID         json.Number `json:"id"`
			Attributes struct {
				Username string `json:"username"`
				Name     string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return 0, false
	}

	// The API's search is fuzzy, so require an exact username match rather
	// than accepting the first row (which the old code did).
	for _, d := range payload.Data {
		if strings.EqualFold(d.Attributes.Username, username) {
			id, _ := d.ID.Int64()
			return int(id), true
		}
	}
	return 0, false
}

// EnumerateViaProfilePages walks numeric user IDs looking for exposed profile
// or contact pages. IDs are bounded and the range is validated so a typo
// cannot launch an unbounded scan.
func (ue *UserEnumerator) EnumerateViaProfilePages(ctx context.Context, targetURL string, startID, maxID int) ([]models.User, error) {
	base := NormalizeTarget(targetURL)

	if startID < 1 {
		startID = 1
	}
	if maxID < startID {
		return nil, fmt.Errorf("invalid ID range: %d-%d", startID, maxID)
	}
	if maxID-startID > 100000 {
		return nil, fmt.Errorf("ID range %d-%d too large (max 100000)", startID, maxID)
	}

	var (
		mu  sync.Mutex
		out []models.User
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, ue.threads)

	for id := startID; id <= maxID; id++ {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(userID int) {
			defer wg.Done()
			defer func() { <-sem }()

			endpoint := fmt.Sprintf("%s/index.php?option=com_contact&view=contact&id=%d", base, userID)
			resp, err := ue.client.Get(ctx, endpoint)
			if err != nil || resp.StatusCode != 200 {
				return
			}

			name := extractContactName(resp.String())
			if name == "" {
				return
			}

			u := models.User{Username: name, ID: userID, Found: true, Method: "contact-page"}

			mu.Lock()
			out = append(out, u)
			mu.Unlock()

			if ue.OnFound != nil {
				ue.OnFound(u)
			}
		}(id)
	}

	wg.Wait()
	return out, ctx.Err()
}

// extractContactName pulls a person's name from a com_contact page, ignoring
// error and "not found" pages.
func extractContactName(body string) string {
	m := reContactName.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	name := strings.TrimSpace(stripTags(m[1]))
	lower := strings.ToLower(name)
	for _, bad := range []string{"error", "not found", "not authorised", "forbidden", "404"} {
		if strings.Contains(lower, bad) {
			return ""
		}
	}
	if name == "" || len(name) > 120 {
		return ""
	}
	return name
}
