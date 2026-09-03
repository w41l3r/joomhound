package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/lfgrillo83/joomhound/internal/bruteforce"
	"github.com/lfgrillo83/joomhound/internal/cve"
	"github.com/lfgrillo83/joomhound/internal/enum"
	"github.com/lfgrillo83/joomhound/internal/http"
	"github.com/lfgrillo83/joomhound/internal/models"
)

type ScanConfig struct {
	Target          string
	Threads         int
	Timeout         time.Duration
	ProxyURL        string
	VerifySSL       bool
	UserAgent       string
	FollowRedirects bool

	// Enumeration options
	CheckVersion    bool
	CheckComponents bool
	CheckTemplates  bool
	CheckPlugins    bool
	CheckCVEs       bool

	// Brute-force options
	EnableBruteForce bool
	UserWordlist     []string
	PasswordWordlist []string
	UserMethod       string

	// Output options
	OutputFormat string
	Verbose      bool
}

type Scanner struct {
	config    ScanConfig
	client    *http.Client
	detector  *enum.Detector
	cveDB     *cve.Database
	startTime time.Time
	result    *models.ScanResult
}

// NewScanner creates a new scanner instance
func NewScanner(config ScanConfig) (*Scanner, error) {
	// Create HTTP client
	clientConfig := http.ClientConfig{
		Timeout:         config.Timeout,
		ProxyURL:        config.ProxyURL,
		VerifySSL:       config.VerifySSL,
		UserAgent:       config.UserAgent,
		RateLimit:       10.0, // 10 requests per second
		MaxConnections:  config.Threads,
		FollowRedirects: config.FollowRedirects,
	}

	httpClient, err := http.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		config:   config,
		client:   httpClient,
		detector: enum.NewDetector(httpClient),
		cveDB:    cve.NewDatabase(),
		startTime: time.Now(),
		result: &models.ScanResult{
			Target:          config.Target,
			Components:      []models.Component{},
			Templates:       []models.Template{},
			Users:           []models.User{},
			Vulnerabilities: []models.Vulnerability{},
			Metadata: models.ScanMetadata{
				Errors: []string{},
			},
		},
	}, nil
}

// Scan performs the full scan
func (s *Scanner) Scan() *models.ScanResult {
	s.result.Metadata.StartTime = s.startTime.Format(time.RFC3339)

	if s.config.Verbose {
		fmt.Printf("[*] Starting scan on %s\n", s.config.Target)
	}

	// Step 1: Detect Joomla
	if s.config.Verbose {
		fmt.Println("[*] Detecting Joomla...")
	}
	s.detectJoomla()

	if !s.result.JoomlaDetected {
		if s.config.Verbose {
			fmt.Println("[-] Joomla not detected")
		}
		s.finalizeScan()
		return s.result
	}

	var wg sync.WaitGroup

	// Step 2: Detect version
	if s.config.CheckVersion {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.config.Verbose {
				fmt.Println("[*] Detecting version...")
			}
			s.detectVersion()
		}()
	}

	// Step 3: Enumerate components
	if s.config.CheckComponents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.config.Verbose {
				fmt.Println("[*] Enumerating components...")
			}
			s.enumerateComponents()
		}()
	}

	// Step 4: Enumerate templates
	if s.config.CheckTemplates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.config.Verbose {
				fmt.Println("[*] Enumerating templates...")
			}
			s.enumerateTemplates()
		}()
	}

	wg.Wait()

	// Step 5: Check for CVEs (based on version and components)
	if s.config.CheckCVEs {
		if s.config.Verbose {
			fmt.Println("[*] Checking for CVEs...")
		}
		s.checkCVEs()
	}

	// Step 6: Brute-force users
	if s.config.EnableBruteForce && len(s.config.UserWordlist) > 0 {
		if s.config.Verbose {
			fmt.Println("[*] Enumerating users...")
		}
		s.enumerateUsers()

		// Step 7: Brute-force passwords (if users found)
		if len(s.result.Users) > 0 && len(s.config.PasswordWordlist) > 0 {
			if s.config.Verbose {
				fmt.Println("[*] Attempting password brute-force...")
			}
			s.bruteForcePasswords()
		}
	}

	s.finalizeScan()
	return s.result
}

// detectJoomla checks if target is running Joomla
func (s *Scanner) detectJoomla() {
	s.result.JoomlaDetected = s.detector.DetectJoomla(s.config.Target)
}

// detectVersion detects Joomla version
func (s *Scanner) detectVersion() {
	s.result.Version = *s.detector.DetectVersion(s.config.Target)
}

// enumerateComponents finds installed components
func (s *Scanner) enumerateComponents() {
	components := s.detector.EnumerateComponents(s.config.Target)
	s.result.Components = components

	if s.config.Verbose {
		fmt.Printf("[+] Found %d components\n", len(components))
	}
}

// enumerateTemplates finds installed templates
func (s *Scanner) enumerateTemplates() {
	templates := s.detector.EnumerateTemplates(s.config.Target)
	s.result.Templates = templates

	if s.config.Verbose {
		fmt.Printf("[+] Found %d templates\n", len(templates))
	}
}

// checkCVEs checks for known vulnerabilities
func (s *Scanner) checkCVEs() {
	var vulnerabilities []models.Vulnerability

	// Check based on version
	if s.result.Version.Detected {
		cves := s.cveDB.SearchByVersion(s.result.Version.Version)
		for _, cveEntry := range cves {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				CVE:         cveEntry.CVE,
				Title:       cveEntry.Title,
				Description: cveEntry.Description,
				CVSS:        cveEntry.CVSS,
				Reference:   cveEntry.References[0],
			})
		}
	}

	// Check based on components
	for _, comp := range s.result.Components {
		cves := s.cveDB.SearchByComponent(comp.Name)
		for _, cveEntry := range cves {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				CVE:         cveEntry.CVE,
				Title:       cveEntry.Title,
				Description: cveEntry.Description,
				CVSS:        cveEntry.CVSS,
				Affected:    []string{comp.Name},
				Reference:   cveEntry.References[0],
			})
		}
	}

	s.result.Vulnerabilities = vulnerabilities

	if s.config.Verbose {
		fmt.Printf("[+] Found %d potential vulnerabilities\n", len(vulnerabilities))
	}
}

// enumerateUsers attempts to find valid usernames
func (s *Scanner) enumerateUsers() {
	enumerator := bruteforce.NewUserEnumerator(s.client, s.config.Threads)
	users := enumerator.EnumerateUsers(s.config.Target, s.config.UserWordlist)
	s.result.Users = users

	if s.config.Verbose {
		fmt.Printf("[+] Enumerated %d users\n", len(users))
	}
}

// bruteForcePasswords attempts to crack passwords for found users
func (s *Scanner) bruteForcePasswords() {
	bruteforcer := bruteforce.NewPasswordBruteforcer(s.client, s.config.Threads)

	for i, user := range s.result.Users {
		if s.config.Verbose {
			fmt.Printf("[*] Brute-forcing passwords for user: %s\n", user.Username)
		}

		result := bruteforcer.BruteForcePassword(
			s.config.Target,
			user.Username,
			s.config.PasswordWordlist,
		)

		s.result.Users[i] = *result

		if result.PasswordValid {
			if s.config.Verbose {
				fmt.Printf("[+] Valid credentials found: %s:%s\n", result.Username, result.Password)
			}
		}
	}
}

// finalizeScan finalizes the scan and collects metadata
func (s *Scanner) finalizeScan() {
	endTime := time.Now()
	duration := endTime.Sub(s.startTime)

	s.result.Metadata.EndTime = endTime.Format(time.RFC3339)
	s.result.Metadata.Duration = duration.String()
	s.result.Metadata.HTTPRequests = 0 // This should be tracked by the HTTP client

	if s.config.Verbose {
		fmt.Printf("\n[*] Scan completed in %s\n", duration.String())
	}
}

// GetResult returns the scan result
func (s *Scanner) GetResult() *models.ScanResult {
	return s.result
}
