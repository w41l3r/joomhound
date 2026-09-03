package commands

import (
	"os"

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
	Long: `JoomHound enumerates and tests Joomla installations.

It combines techniques from droopescan (fingerprinting), JoomlaScan
(component discovery) and OWASP joomscan (version detection), with live CVE
correlation against NVD and the GitHub Advisory Database.

Only use this against systems you are explicitly authorized to test.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

// Execute runs the CLI.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	pf := rootCmd.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default $HOME/.joomhound/config.yaml)")
	pf.BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	pf.BoolVarP(&quiet, "quiet", "q", false, "suppress the banner")
	pf.IntVar(&timeoutSecs, "timeout", 20, "HTTP request timeout in seconds")
	pf.IntVarP(&threads, "threads", "T", 10, "number of concurrent workers")
	pf.StringVar(&proxyURL, "proxy", "", "proxy URL (http://host:port or socks5://host:port)")
	pf.Float64Var(&rateLimit, "rate-limit", 10, "maximum requests per second against the target (0 = unlimited)")
	pf.StringVar(&userAgent, "user-agent", "", "custom User-Agent header")
	// Default false preserves the pentest-friendly behaviour of accepting
	// self-signed certificates, but it is now an explicit, documented choice.
	pf.BoolVar(&verifySSL, "verify-ssl", false, "verify TLS certificates")
	pf.BoolVar(&noRedirects, "no-redirects", false, "do not follow HTTP redirects")

	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(bruteCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(cveCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			viper.AddConfigPath(home + "/.joomhound")
		}
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("JOOMHOUND")
	viper.AutomaticEnv()

	_ = viper.ReadInConfig()
}
