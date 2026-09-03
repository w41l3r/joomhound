package commands

import (
	"fmt"
	"time"

	"github.com/w41l3r/joomhound/internal/utils"
	"github.com/spf13/cobra"
)

var bruteCmd = &cobra.Command{
	Use:   "brute -t <target> [flags]",
	Short: "Enumerate users and test credentials against a Joomla installation",
	Long: `Perform credential testing against a Joomla installation.

User enumeration only reports a username when the target's response provably
differs from a known-nonexistent-username baseline, so it does not report
every candidate as valid.

Password testing sends a real Joomla login (session cookie + CSRF token) and
aborts automatically when account lockout, rate limiting or a WAF is detected.`,
	Example: `  joomhound brute -t https://target.tld --users users.txt --passwords pass.txt
  joomhound brute -t https://target.tld -u admin -p rockyou.txt --brute-delay 500`,
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

		return runScan(cmd, cfg, outPath, resolveFormat(cmd, outPath))
	},
}

func init() {
	f := bruteCmd.Flags()
	f.StringP("target", "t", "", "target URL (required)")
	f.String("users", "", "username wordlist for enumeration")
	f.StringP("user", "u", "", "test a single known username (skips enumeration)")
	f.StringP("passwords", "p", "", "password wordlist")
	f.StringP("output", "o", "", "output file (default: stdout)")
	f.StringP("format", "f", "", "output format: text, json, xml, markdown")
	f.BoolP("json", "j", false, "shorthand for --format json")
	f.Int("brute-delay", 0, "extra delay between login attempts in milliseconds")

	_ = bruteCmd.MarkFlagRequired("target")
}
