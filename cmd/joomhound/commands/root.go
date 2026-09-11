package commands

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version is the tool version, overridable at build time with
// -ldflags "-X .../commands.Version=x.y.z".
var Version = "1.0.0"

// Persistent (global) flag values.
var (
	cfgFile     string
	verbose     bool
	timeoutSecs int
	threads     int
	proxyURL    string
	rateLimit   float64
	userAgent   string
	verifySSL   bool
	noRedirects bool
	quiet       bool
)

var rootCmd = &cobra.Command{
	Use:   "joomhound",
	Short: "JoomHound - Joomla enumeration and credential testing",
	Long: `JoomHound fingerprints, enumerates and tests Joomla installations.

It combines techniques from droopescan (fingerprinting), JoomlaScan
(component discovery) and OWASP joomscan (version detection), with live CVE
correlation against NVD and the GitHub Advisory Database.

TARGET URL
  Commands that contact a site (scan, enum and brute) require -t/--target.
  Pass the absolute base URL of the Joomla installation, including http:// or
  https://. A port and a path are supported, for example:

    joomhound enum --target https://host.example:8443/joomla

  The cve command does not take a target URL; it looks up a known Joomla
  version or component directly.

CONFIGURATION
  Passive defaults can be loaded from $HOME/.joomhound/config.yaml or an
  explicit --config file. Precedence is: command-line flags, JOOMHOUND_*
  environment variables, config file, built-in defaults. Targets, credential
  wordlists, --brute and destructive operations remain command-line only.

Only use this against systems you are explicitly authorized to test.`,
	Example: `  # Enumerate without testing credentials (best first command)
  joomhound enum --target https://target.example

  # Run the complete fingerprint/enumeration/CVE workflow
  joomhound scan -t https://target.example/joomla -o report.json

  # Test one known account with an explicit password wordlist
  joomhound brute -t https://target.example -u admin -p passwords.txt

  # Look up CVEs without contacting a Joomla target
  joomhound cve --version 4.2.7`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return loadAndApplyConfig(cmd)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

// Execute runs the CLI.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "configuration file (default: $HOME/.joomhound/config.yaml)")
	pf.BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	pf.BoolVarP(&quiet, "quiet", "q", false, "suppress the banner")
	pf.IntVar(&timeoutSecs, "timeout", 20, "HTTP request timeout in seconds")
	pf.IntVarP(&threads, "threads", "T", 10, "number of concurrent workers")
	pf.StringVar(&proxyURL, "proxy", "", "proxy URL (http://host:port or socks5://host:port)")
	pf.Float64Var(&rateLimit, "rate-limit", 10, "maximum requests per second against the target (non-positive values reset to 10)")
	pf.StringVar(&userAgent, "user-agent", "", "custom User-Agent header")
	// Default false preserves the pentest-friendly behaviour of accepting
	// self-signed certificates, but it is now an explicit, documented choice.
	pf.BoolVar(&verifySSL, "verify-ssl", false, "verify TLS certificates (disabled by default for self-signed targets)")
	pf.BoolVar(&noRedirects, "no-redirects", false, "do not follow HTTP redirects")

	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(bruteCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(cveCmd)
}

type configBinding struct {
	flag string
	keys []string
}

var commonConfigBindings = []configBinding{
	{flag: "verbose", keys: []string{"verbose"}},
	{flag: "quiet", keys: []string{"quiet"}},
	{flag: "timeout", keys: []string{"timeout", "http.timeout"}},
	{flag: "threads", keys: []string{"threads", "scan.threads"}},
	{flag: "proxy", keys: []string{"proxy", "proxy-url"}},
	{flag: "rate-limit", keys: []string{"rate-limit", "http.rate_limit"}},
	{flag: "user-agent", keys: []string{"user-agent", "scan.user_agent"}},
	{flag: "verify-ssl", keys: []string{"verify-ssl", "http.verify_ssl"}},
	{flag: "no-redirects", keys: []string{"no-redirects"}},
	{flag: "format", keys: []string{"format", "output.format"}},
	{flag: "version-detect", keys: []string{"version-detect", "enum.check_version"}},
	{flag: "components", keys: []string{"components", "enum.check_components"}},
	{flag: "templates", keys: []string{"templates", "enum.check_templates"}},
	{flag: "cve", keys: []string{"cve", "enum.check_cves"}},
	{flag: "cve-online", keys: []string{"cve-online"}},
	{flag: "cve-cache-dir", keys: []string{"cve-cache-dir"}},
	{flag: "cve-cache-ttl", keys: []string{"cve-cache-ttl"}},
	{flag: "nvd-api-key", keys: []string{"nvd-api-key"}},
	{flag: "github-token", keys: []string{"github-token"}},
	{flag: "brute-delay", keys: []string{"brute-delay", "bruteforce.delay_between_attempts"}},
}

// loadAndApplyConfig applies non-destructive defaults to the command being
// executed. Target selection, credential wordlists, --brute and cache purge
// intentionally remain CLI-only so a stale config cannot trigger an active
// test or destructive action unexpectedly.
func loadAndApplyConfig(cmd *cobra.Command) error {
	v := viper.New()
	v.SetEnvPrefix("JOOMHOUND")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home + "/.joomhound")
		}
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if cfgFile != "" || !errors.As(err, &notFound) {
			return fmt.Errorf("reading configuration: %w", err)
		}
	}

	bindings := append([]configBinding(nil), commonConfigBindings...)
	if cmd.Name() == "cve" {
		bindings = append(bindings,
			configBinding{flag: "online", keys: []string{"cve-online"}},
			configBinding{flag: "cache-dir", keys: []string{"cve-cache-dir"}},
			configBinding{flag: "cache-ttl", keys: []string{"cve-cache-ttl"}},
		)
	}

	for _, binding := range bindings {
		flag := cmd.Flags().Lookup(binding.flag)
		if flag == nil || flag.Changed {
			continue
		}

		value, key, ok := firstConfigValue(v, binding.keys)
		if !ok {
			continue
		}
		if err := flag.Value.Set(fmt.Sprint(value)); err != nil {
			return fmt.Errorf("invalid configuration value for %q from %q: %w",
				binding.flag, key, err)
		}
	}

	return nil
}

func firstConfigValue(v *viper.Viper, keys []string) (value any, key string, ok bool) {
	for _, key := range keys {
		if v.IsSet(key) {
			value := v.Get(key)
			// Command flags in this tool accept scalar values. Ignore an old
			// nested section with the same name (for example `proxy: { ... }`)
			// instead of converting the map to a bogus flag string.
			switch value.(type) {
			case map[string]any, []any:
				continue
			}
			return value, key, true
		}
	}
	return nil, "", false
}
