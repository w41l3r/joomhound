package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/w41l3r/joomhound/internal/utils"
)

var bruteCmd = &cobra.Command{
	Use:   "brute --target <url> [flags]",
	Short: "Enumerate users and test credentials against a Joomla installation",
	Long: `Perform credential testing against a Joomla installation.

Pass the target with -t/--target as an absolute URL including its scheme.
Paths and non-default ports are supported.

User enumeration uses exact username matches from Joomla's unauthenticated
public API. If that API is unavailable, enumeration is skipped; JoomHound
never submits registration forms as a username-existence probe. Use
-u/--user to test a username you already know.

Password testing sends a real Joomla login (session cookie + CSRF token) and
aborts automatically when account lockout, rate limiting or a WAF is detected.
Verbose output reports progress and final candidate counts without printing
candidate passwords. Request failures are reported as inconclusive checks,
not as rejected passwords. Reports distinguish an operator-supplied username
from one discovered through the public API.

If --users or --passwords is omitted, a small built-in list is used. This
command makes real login attempts; review the selected users, wordlist,
concurrency and rate limit before running it.`,
	Example: `  joomhound brute -t https://target.example --users users.txt --passwords pass.txt
  joomhound brute -t https://target.example:8443/joomla -u admin -p rockyou.txt --brute-delay 500`,
	Args: targetCommandArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		outPath, _ := cmd.Flags().GetString("output")
		singleUser, _ := cmd.Flags().GetString("user")
		usersPath, _ := cmd.Flags().GetString("users")
		passPath, _ := cmd.Flags().GetString("passwords")

		var userList []string
		switch {
		case singleUser != "":
			userList = []string{singleUser}
		default:
			var err error
			userList, err = loadWordlist(usersPath, utils.DefaultUsernames)
			if err != nil {
				return err
			}
		}

		passList, err := loadWordlist(passPath, utils.DefaultPasswords)
		if err != nil {
			return err
		}
		if len(passList) == 0 {
			return fmt.Errorf("no passwords to test: supply --passwords")
		}

		cfg := baseScanConfig(target)
		cfg.CheckVersion = true
		cfg.EnableBruteForce = true
		cfg.PasswordWordlist = passList

		if singleUser != "" {
			// Skip enumeration entirely and go straight at the named account.
			cfg.UserWordlist = nil
			cfg.SkipUserEnumeration = true
			cfg.KnownUsers = userList
		} else {
			cfg.UserWordlist = userList
		}

		if delayMs, _ := cmd.Flags().GetInt("brute-delay"); delayMs > 0 {
			cfg.BruteDelay = time.Duration(delayMs) * time.Millisecond
		}

		format, err := resolveFormat(cmd, outPath)
		if err != nil {
			return err
		}
		return runScan(cmd, cfg, outPath, format)
	},
}

func init() {
	f := bruteCmd.Flags()
	f.StringP("target", "t", "", targetFlagHelp)
	f.String("users", "", "username wordlist for enumeration, one entry per line (default: small built-in list)")
	f.StringP("user", "u", "", "test a single known username (skips enumeration)")
	f.StringP("passwords", "p", "", "password wordlist, one entry per line (default: small built-in list)")
	f.StringP("output", "o", "", "output file (default: stdout)")
	f.StringP("format", "f", "", "output format: text, json, xml, markdown")
	f.BoolP("json", "j", false, "shorthand for --format json")
	f.Int("brute-delay", 0, "extra delay between login attempts in milliseconds")

	_ = bruteCmd.MarkFlagRequired("target")
}
