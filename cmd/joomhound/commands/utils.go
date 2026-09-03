package commands

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/w41l3r/joomhound/internal/models"
	"github.com/w41l3r/joomhound/internal/output"
	"github.com/w41l3r/joomhound/internal/scanner"
	"github.com/w41l3r/joomhound/internal/utils"
	"github.com/spf13/cobra"
)

// signalContext returns a context cancelled on SIGINT/SIGTERM so a running
// scan stops cleanly instead of being killed mid-request.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// validateTarget checks that the target is a usable absolute HTTP(S) URL.
//
// The previous isValidURL ended in `|| len(urlString) > 0`, which made it
// return true for literally any non-empty string.
func validateTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target URL is required")
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("target %q must start with http:// or https://", target)
	}

	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL %q: %w", target, err)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid target URL %q: missing host", target)
	}
	return nil
}

// loadWordlist loads a wordlist from disk, falling back to built-in defaults.
func loadWordlist(path string, defaults func() []string) ([]string, error) {
	if path == "" {
		if defaults != nil {
			return defaults(), nil
		}
		return nil, nil
	}

	words, err := utils.LoadWordlist(path)
	if err != nil {
		return nil, fmt.Errorf("loading wordlist %s: %w", path, err)
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("wordlist %s is empty", path)
	}
	return words, nil
}

// baseScanConfig builds a ScanConfig from the global flags.
func baseScanConfig(target string) scanner.ScanConfig {
	return scanner.ScanConfig{
		Target:          target,
		Threads:         threads,
		Timeout:         time.Duration(timeoutSecs) * time.Second,
		ProxyURL:        proxyURL,
		VerifySSL:       verifySSL,
		UserAgent:       userAgent,
		FollowRedirects: !noRedirects,
		RateLimit:       rateLimit,
		Verbose:         verbose,
	}
}

// runScan executes a scan and writes the report.
func runScan(cmd *cobra.Command, cfg scanner.ScanConfig, outPath, format string) error {
	if err := validateTarget(cfg.Target); err != nil {
		return err
	}

	if !quiet {
		printBanner()
	}

	if !cfg.VerifySSL {
		fmt.Fprintln(os.Stderr, "[!] TLS certificate verification is disabled (--verify-ssl to enable)")
	}

	ctx, cancel := signalContext()
	defer cancel()

	s, err := scanner.NewScanner(cfg)
	if err != nil {
		return err
	}

	result := s.Scan(ctx)

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\n[!] Interrupted - writing partial results")
	}

	return writeReport(result, outPath, format)
}

// writeReport formats and emits the result.
func writeReport(result *models.ScanResult, outPath, format string) error {
	formatter := output.NewFormatter(format)

	rendered, err := formatter.Format(result)
	if err != nil {
		return fmt.Errorf("formatting report: %w", err)
	}

	if outPath == "" {
		fmt.Print(rendered)
		return nil
	}

	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating output directory %s: %w", dir, err)
		}
	}

	// 0600: scan output can contain valid credentials.
	if err := os.WriteFile(outPath, []byte(rendered), 0o600); err != nil {
		return fmt.Errorf("writing report to %s: %w", outPath, err)
	}

	fmt.Printf("[+] Report written to %s\n", outPath)
	return nil
}

// resolveFormat picks the output format from the --format/--json flags and the
// output file extension.
func resolveFormat(cmd *cobra.Command, outPath string) string {
	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		return "json"
	}
	if f, _ := cmd.Flags().GetString("format"); f != "" {
		return f
	}
	switch strings.ToLower(filepath.Ext(outPath)) {
	case ".json":
		return "json"
	case ".xml":
		return "xml"
	case ".md", ".markdown":
		return "markdown"
	}
	return "text"
}

func printBanner() {
	fmt.Printf(`
    ╔═══════════════════════════════════════╗
    ║           JoomHound v%-8s         ║
    ║   Joomla Enumeration & Cred Testing   ║
    ╚═══════════════════════════════════════╝

`, Version)
}
