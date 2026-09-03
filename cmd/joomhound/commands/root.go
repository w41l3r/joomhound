package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	timeout int
	threads int
	proxy   string
)

var rootCmd = &cobra.Command{
	Use:   "joomhound",
	Short: "JoomHound - Advanced Joomla Enumeration & Brute-force Tool",
	Long: `JoomHound is a powerful tool for enumerating and brute-forcing Joomla installations.
It combines the best features from droopescan, JoomlaScan, and joomscan (OWASP).

Version: 1.0.0`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return nil
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.joomhound/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "", 30, "HTTP request timeout in seconds")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 10, "number of concurrent threads")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "proxy URL (http://host:port or socks5://host:port)")

	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(bruteCmd)
	rootCmd.AddCommand(scanCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home + "/.joomhound")
		}
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	_ = viper.ReadInConfig()
}
