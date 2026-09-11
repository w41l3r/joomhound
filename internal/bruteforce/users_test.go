package bruteforce

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	jhhttp "github.com/w41l3r/joomhound/internal/http"
)

func newUserTestClient(t *testing.T) *jhhttp.Client {
	t.Helper()
	client, err := jhhttp.NewClient(jhhttp.ClientConfig{FollowRedirects: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestEnumerateUsersUsesExactPublicAPIMatchesAndGETOnly(t *testing.T) {
	var nonGET atomic.Int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Method != nethttp.MethodGet {
			nonGET.Add(1)
		}
		if r.URL.Path != "/api/index.php/v1/users" {
			nethttp.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("filter[search]") {
		case "":
			fmt.Fprint(w, `{"data":[]}`)
		case "admin", "adm":
			// The API may return fuzzy matches. Only the exact "admin"
			// candidate is valid evidence.
			fmt.Fprint(w, `{"data":[{"id":"42","attributes":{"username":"Admin","name":"Administrator"}}]}`)
		default:
			fmt.Fprint(w, `{"data":[]}`)
		}
	}))
	defer srv.Close()

	ue := NewUserEnumerator(newUserTestClient(t), 2)
	users, err := ue.EnumerateUsers(context.Background(), srv.URL,
		[]string{"admin", "adm", "missing"})
	if err != nil {
		t.Fatalf("EnumerateUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users (%+v), want only the exact match", len(users), users)
	}
	if got := users[0]; !strings.EqualFold(got.Username, "admin") || got.ID != 42 || got.Method != "public-api" {
		t.Fatalf("unexpected user: %+v", got)
	}
	if got := nonGET.Load(); got != 0 {
		t.Fatalf("enumeration sent %d non-GET requests, want 0", got)
	}
}

func TestEnumerateUsersSkipsWhenPublicAPIIsUnavailable(t *testing.T) {
	var requests atomic.Int32
	var nonGET atomic.Int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		requests.Add(1)
		if r.Method != nethttp.MethodGet {
			nonGET.Add(1)
		}
		w.WriteHeader(nethttp.StatusForbidden)
	}))
	defer srv.Close()

	var message string
	ue := NewUserEnumerator(newUserTestClient(t), 4)
	ue.OnMessage = func(msg string) { message = msg }
	users, err := ue.EnumerateUsers(context.Background(), srv.URL,
		[]string{"admin", "root", "operator"})
	if err != nil {
		t.Fatalf("EnumerateUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("got users on an unavailable API: %+v", users)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want only the API capability probe", got)
	}
	if got := nonGET.Load(); got != 0 {
		t.Fatalf("enumeration sent %d non-GET requests, want 0", got)
	}
	if !strings.Contains(message, "public Joomla API is unavailable") {
		t.Fatalf("message = %q, want an actionable API-unavailable explanation", message)
	}
}
