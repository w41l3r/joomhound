package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootHelpExplainsHowToSupplyTarget(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	defer rootCmd.SetOut(nil)

	if err := rootCmd.Help(); err != nil {
		t.Fatalf("Help: %v", err)
	}

	help := out.String()
	for _, want := range []string{
		"Commands that contact a site (scan, enum and brute) require -t/--target.",
		"including http:// or",
		"joomhound enum --target https://host.example:8443/joomla",
		"joomhound cve --version 4.2.7",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("root help does not contain %q\n\n%s", want, help)
		}
	}
}

func TestTargetCommandHelpDescribesURLFormat(t *testing.T) {
	for _, cmd := range []*cobra.Command{enumCmd, scanCmd, bruteCmd} {
		t.Run(cmd.Name(), func(t *testing.T) {
			var out bytes.Buffer
			cmd.SetOut(&out)
			defer cmd.SetOut(nil)

			if err := cmd.Help(); err != nil {
				t.Fatalf("Help: %v", err)
			}

			help := out.String()
			if !strings.Contains(help, "Pass the target with -t/--target") {
				t.Errorf("command help does not explain --target:\n%s", help)
			}
			if !strings.Contains(help, targetFlagHelp) {
				t.Errorf("target flag does not describe the URL format:\n%s", help)
			}
		})
	}
}

func TestPositionalTargetGetsActionableError(t *testing.T) {
	if err := targetCommandArgs(enumCmd, nil); err != nil {
		t.Fatalf("no arguments should be accepted: %v", err)
	}

	err := targetCommandArgs(enumCmd, []string{"https://target.example"})
	if err == nil {
		t.Fatal("expected an error for a positional target")
	}
	for _, want := range []string{"does not accept a positional target", "--target https://target.example"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestTLSWarningOnlyAppliesToUnverifiedHTTPS(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		verifySSL bool
		want      bool
	}{
		{name: "HTTP target", target: "http://target.example", want: false},
		{name: "unverified HTTPS", target: "https://target.example", want: true},
		{name: "verified HTTPS", target: "https://target.example", verifySSL: true, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldWarnAboutTLS(tc.target, tc.verifySSL); got != tc.want {
				t.Fatalf("shouldWarnAboutTLS(%q, %v) = %v, want %v",
					tc.target, tc.verifySSL, got, tc.want)
			}
		})
	}
}
