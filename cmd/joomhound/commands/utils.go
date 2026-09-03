package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/lfgrillo83/joomhound/internal/scanner"
	"github.com/lfgrillo83/joomhound/internal/utils"
	"github.com/spf13/cobra"
)

// loadWordlist loads a wordlist from a file or returns defaults
func loadWordlist(filepath string, useDefaults bool, defaultsFunc func() []string) ([]string, error) {
	if filepath == "" {
		if useDefaults {
			return defaultsFunc(), nil
		}
		return []string{}, nil
	}

	words, err := utils.LoadWordlist(filepath)
	if err != nil {
		if useDefaults {
			fmt.Printf("[-] Could not load wordlist %s, using defaults: %v\n", filepath, err)
			return defaultsFunc(), nil
		}
		return nil, err
	}

	return words, nil
}

// createScanConfig creates a ScanConfig from command-line flags
func createScanConfig(cmd *cobra.Command) (scanner.ScanConfig, error) {
	target, _ := cmd.Flags().GetString("target")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	verifySSL, _ := cmd.Flags().GetBool("verify-ssl")
	timeoutSeconds, _ := cmd.Flags().GetInt("timeout")
	threadsCount, _ := cmd.Flags().GetInt("threads")

	config := scanner.ScanConfig{
		Target:          target,
		Threads:         threadsCount,
		Timeout:         time.Duration(timeoutSeconds) * time.Second,
		ProxyURL:        proxyURL,
		VerifySSL:       verifySSL,
		FollowRedirects: true,
		Verbose:         verbose,
	}

	return config, nil
}

// validateTarget validates that the target is a valid URL
func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target URL is required")
	}

	if !isValidURL(target) {
		return fmt.Errorf("invalid URL format: %s", target)
	}

	return nil
}

// isValidURL performs basic URL validation
func isValidURL(urlString string) bool {
	// Basic validation - should start with http:// or https://
	return (len(urlString) > 7 &&
		(urlString[:7] == "http://" || urlString[:8] == "https://")) ||
		urlString == "localhost" ||
		len(urlString) > 0
}

// ensureResultsDir creates the results directory if it doesn't exist
func ensureResultsDir(dir string) error {
	if dir == "" {
		dir = "./results"
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}

	return nil
}

// printBanner prints the JoomHound banner
func printBanner() {
	fmt.Println(`
     ╔═══════════════════════════════════════╗
     ║      🦁 JoomHound v1.0.0 🦁          ║
     ║   Advanced Joomla Enumeration Tool   ║
     ╚═══════════════════════════════════════╝
`)
}
