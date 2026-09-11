package commands

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/w41l3r/joomhound/internal/models"
	"github.com/w41l3r/joomhound/internal/output"
	"github.com/w41l3r/joomhound/internal/scanner"
	"github.com/w41l3r/joomhound/internal/utils"
)

const targetFlagHelp = "base URL of the Joomla installation; include http:// or https:// (required)"

// targetCommandArgs rejects positional URLs with an actionable error. Target
// commands deliberately use -t/--target, but a bare URL is an easy mistake to
// make when arriving from another scanner's CLI.
func targetCommandArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}

	return fmt.Errorf(
		"%s does not accept a positional target; use --target, for example: %s --target https://target.example",
		cmd.CommandPath(), cmd.CommandPath(),
	)
}

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
	normalizedFormat, err := output.NormalizeFormat(format)
	if err != nil {
		return err
	}
	format = normalizedFormat

	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()
	cfg.LogWriter = stderr

	if !quiet {
		printBanner(stderr)
	}

	if shouldWarnAboutTLS(cfg.Target, cfg.VerifySSL) {
		fmt.Fprintln(stderr, "[!] TLS certificate verification is disabled (--verify-ssl to enable)")
	}

	ctx, cancel := signalContext()
	defer cancel()

	s, err := scanner.NewScanner(cfg)
	if err != nil {
		return err
	}

	result := s.Scan(ctx)

	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "\n[!] Interrupted - writing partial results")
	}

	return writeReport(result, outPath, format, stdout, stderr)
}

func shouldWarnAboutTLS(target string, verifySSL bool) bool {
	if verifySSL {
		return false
	}
	u, err := url.Parse(target)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// writeReport formats and emits the result.
func writeReport(result *models.ScanResult, outPath, format string, stdout, stderr io.Writer) error {
	formatter, err := output.NewFormatter(format)
	if err != nil {
		return err
	}

	rendered, err := formatter.Format(result)
	if err != nil {
		return fmt.Errorf("formatting report: %w", err)
	}

	if outPath == "" {
		_, err := fmt.Fprint(stdout, rendered)
		if err != nil {
			return fmt.Errorf("writing report to stdout: %w", err)
		}
		return nil
	}

	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating output directory %s: %w", dir, err)
		}
	}

	// Write beside the destination and rename only after the complete report is
	// durable. A failed/interrupted write therefore leaves an existing report
	// intact instead of replacing it with a partial document.
	tempReport, err := os.CreateTemp(filepath.Dir(outPath), "."+filepath.Base(outPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary report for %s: %w", outPath, err)
	}
	tempPath := tempReport.Name()
	committed := false
	defer func() {
		tempReport.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()

	// 0600: scan output can contain valid credentials. CreateTemp already uses
	// this mode, and the explicit chmod documents and enforces the contract.
	if err := tempReport.Chmod(0o600); err != nil {
		return fmt.Errorf("securing report %s: %w", outPath, err)
	}
	if _, err := io.WriteString(tempReport, rendered); err != nil {
		return fmt.Errorf("writing report to %s: %w", outPath, err)
	}
	if err := tempReport.Sync(); err != nil {
		return fmt.Errorf("syncing report %s: %w", outPath, err)
	}
	if err := tempReport.Close(); err != nil {
		return fmt.Errorf("closing report %s: %w", outPath, err)
	}
	if err := os.Rename(tempPath, outPath); err != nil {
		return fmt.Errorf("committing report %s: %w", outPath, err)
	}
	committed = true

	fmt.Fprintf(stderr, "[+] Report written to %s\n", outPath)
	return nil
}

// resolveFormat picks the output format from the --format/--json flags and the
// output file extension.
func resolveFormat(cmd *cobra.Command, outPath string) (string, error) {
	explicit, _ := cmd.Flags().GetString("format")
	var configured string
	if strings.TrimSpace(explicit) != "" || cmd.Flags().Changed("format") {
		var err error
		configured, err = output.NormalizeFormat(explicit)
		if err != nil {
			return "", err
		}
	}

	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		if cmd.Flags().Changed("format") && !strings.EqualFold(strings.TrimSpace(explicit), "json") {
			return "", fmt.Errorf("--json cannot be combined with --format %q", explicit)
		}
		return "json", nil
	}
	if cmd.Flags().Changed("format") {
		return configured, nil
	}

	// An output path is itself an explicit CLI choice. Its recognized
	// extension therefore beats a passive environment/config default, while
	// an explicit --format still has the highest precedence.
	switch strings.ToLower(filepath.Ext(outPath)) {
	case ".json":
		return "json", nil
	case ".xml":
		return "xml", nil
	case ".md", ".markdown":
		return "markdown", nil
	}
	if configured != "" {
		return configured, nil
	}
	return "text", nil
}

func printBanner(w io.Writer) {
	fmt.Fprintf(w, `
    ╔═══════════════════════════════════════╗
    ║           JoomHound v%-8s         ║
    ║   Joomla Enumeration & Cred Testing   ║
    ╚═══════════════════════════════════════╝

`, Version)
}
