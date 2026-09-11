package commands

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/w41l3r/joomhound/internal/utils"
)

var scanCmd = &cobra.Command{
	Use:   "scan --target <url> [flags]",
	Short: "Full scan of a Joomla installation",
	Long: `Perform a comprehensive scan:
  - Joomla fingerprinting
  - Version detection (manifest, language pack, changelog, generator tag)
  - Component and template enumeration
  - CVE correlation (offline database, or live NVD/GitHub with --cve-online)
  - Optional user enumeration and password testing

Pass the target with -t/--target as an absolute URL including its scheme.
Paths and non-default ports are supported. Credential testing is disabled
unless --brute is supplied.`,
	Example: `  joomhound scan --target https://target.example
  joomhound scan -t https://target.example:8443/joomla --cve-online -o report.json
  joomhound scan -t https://target.example --brute --users users.txt --passwords rockyou.txt`,
	Args: targetCommandArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		outPath, _ := cmd.Flags().GetString("output")

		cfg := baseScanConfig(target)
		cfg.CheckVersion = true
		cfg.CheckComponents = true
		cfg.CheckTemplates = true
		cfg.CheckCVEs = true

		cfg.CveOnlineEnabled, _ = cmd.Flags().GetBool("cve-online")
		cfg.CveCacheDir, _ = cmd.Flags().GetString("cve-cache-dir")
		if ttlHours, _ := cmd.Flags().GetInt("cve-cache-ttl"); ttlHours > 0 {
			cfg.CveCacheTTL = time.Duration(ttlHours) * time.Hour
		}
		cfg.NVDAPIKey, _ = cmd.Flags().GetString("nvd-api-key")
		cfg.GitHubToken, _ = cmd.Flags().GetString("github-token")

		if brute, _ := cmd.Flags().GetBool("brute"); brute {
			usersPath, _ := cmd.Flags().GetString("users")
			passPath, _ := cmd.Flags().GetString("passwords")

			userList, err := loadWordlist(usersPath, utils.DefaultUsernames)
			if err != nil {
				return err
			}
			passList, err := loadWordlist(passPath, utils.DefaultPasswords)
			if err != nil {
				return err
			}

			cfg.EnableBruteForce = true
			cfg.UserWordlist = userList
			cfg.PasswordWordlist = passList

			if delayMs, _ := cmd.Flags().GetInt("brute-delay"); delayMs > 0 {
				cfg.BruteDelay = time.Duration(delayMs) * time.Millisecond
			}
		}

		format, err := resolveFormat(cmd, outPath)
		if err != nil {
			return err
		}
		return runScan(cmd, cfg, outPath, format)
	},
}

func init() {
	f := scanCmd.Flags()
	f.StringP("target", "t", "", targetFlagHelp)
	f.StringP("output", "o", "", "output file (default: stdout)")
	f.StringP("format", "f", "", "output format: text, json, xml, markdown")
	f.BoolP("json", "j", false, "shorthand for --format json")

	// CVE options
	f.Bool("cve-online", false, "query live CVE feeds (NVD + GitHub Advisory Database) in addition to the offline database")
	f.String("cve-cache-dir", "", "CVE cache directory (default $HOME/.joomhound/cache/cve)")
	f.Int("cve-cache-ttl", 24, "CVE cache freshness in hours")
	f.String("nvd-api-key", "", "NVD API key (or set NVD_API_KEY) - raises the provider rate limit")
	f.String("github-token", "", "GitHub token (or set GITHUB_TOKEN) - raises the advisory API rate limit")

	// Brute-force options
	f.Bool("brute", false, "also enumerate users and test passwords (uses built-in lists when omitted)")
	f.String("users", "", "username wordlist, one entry per line (default: small built-in list)")
	f.String("passwords", "", "password wordlist, one entry per line (default: small built-in list)")
	f.Int("brute-delay", 0, "extra delay between login attempts in milliseconds")

	_ = scanCmd.MarkFlagRequired("target")
}
