package commands

import (
	"time"

	"github.com/spf13/cobra"
)

var enumCmd = &cobra.Command{
	Use:   "enum --target <url> [flags]",
	Short: "Enumerate a Joomla installation (no credential testing)",
	Long: `Enumerate Joomla installation details:
  - Version detection
  - Installed components
  - Installed templates

Pass the target with -t/--target as an absolute URL including its scheme.
Paths and non-default ports are supported.

Credential attacks are never performed by this command. CVE correlation uses
the small offline database by default; --cve-online also queries NVD/GitHub.`,
	Example: `  joomhound enum --target https://target.example
  joomhound enum -t https://target.example:8443/joomla --cve-online -o findings.md
  joomhound enum -t https://target.example --components=false --templates=false`,
	Args: targetCommandArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		outPath, _ := cmd.Flags().GetString("output")

		cfg := baseScanConfig(target)
		cfg.CheckVersion, _ = cmd.Flags().GetBool("version-detect")
		cfg.CheckComponents, _ = cmd.Flags().GetBool("components")
		cfg.CheckTemplates, _ = cmd.Flags().GetBool("templates")
		cfg.CheckCVEs, _ = cmd.Flags().GetBool("cve")

		cfg.CveOnlineEnabled, _ = cmd.Flags().GetBool("cve-online")
		if cfg.CveOnlineEnabled {
			// Asking for online CVEs implies wanting CVE correlation at all.
			cfg.CheckCVEs = true
		}
		cfg.CveCacheDir, _ = cmd.Flags().GetString("cve-cache-dir")
		if ttlHours, _ := cmd.Flags().GetInt("cve-cache-ttl"); ttlHours > 0 {
			cfg.CveCacheTTL = time.Duration(ttlHours) * time.Hour
		}
		cfg.NVDAPIKey, _ = cmd.Flags().GetString("nvd-api-key")
		cfg.GitHubToken, _ = cmd.Flags().GetString("github-token")

		format, err := resolveFormat(cmd, outPath)
		if err != nil {
			return err
		}
		return runScan(cmd, cfg, outPath, format)
	},
}

func init() {
	f := enumCmd.Flags()
	f.StringP("target", "t", "", targetFlagHelp)
	f.StringP("output", "o", "", "output file (default: stdout)")
	f.StringP("format", "f", "", "output format: text, json, xml, markdown")
	f.BoolP("json", "j", false, "shorthand for --format json")

	f.Bool("version-detect", true, "detect the Joomla version")
	f.Bool("components", true, "enumerate components")
	f.Bool("templates", true, "enumerate templates")
	f.Bool("cve", true, "correlate findings with CVE data")

	f.Bool("cve-online", false, "query live CVE feeds (NVD + GitHub Advisory Database)")
	f.String("cve-cache-dir", "", "CVE cache directory (default $HOME/.joomhound/cache/cve)")
	f.Int("cve-cache-ttl", 24, "CVE cache freshness in hours")
	f.String("nvd-api-key", "", "NVD API key (or set NVD_API_KEY)")
	f.String("github-token", "", "GitHub token (or set GITHUB_TOKEN)")

	_ = enumCmd.MarkFlagRequired("target")
}
