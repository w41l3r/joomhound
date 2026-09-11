package commands

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/w41l3r/joomhound/internal/cve"
)

var cveCmd = &cobra.Command{
	Use:   "cve [flags]",
	Short: "Look up Joomla CVEs without scanning a target",
	Long: `Query CVE data for a Joomla version or component directly, using the
offline database or the live NVD and GitHub Advisory feeds.

Useful for triaging a version you already know, and for warming the cache
before an engagement where outbound access may be restricted.`,
	Example: `  joomhound cve --version 3.9.4
  joomhound cve --version 4.2.7 --online
  joomhound cve --component com_fields --online
  joomhound cve --purge-cache`,
	RunE: func(cmd *cobra.Command, args []string) error {
		stdout := cmd.OutOrStdout()
		if purge, _ := cmd.Flags().GetBool("purge-cache"); purge {
			dir, _ := cmd.Flags().GetString("cache-dir")
			cache, err := cve.NewDiskCache(dir, 0)
			if err != nil {
				return err
			}
			if err := cache.Purge(); err != nil {
				return fmt.Errorf("purging cache: %w", err)
			}
			fmt.Fprintf(stdout, "[+] CVE cache purged: %s\n", cache.Dir())
			return nil
		}

		version, _ := cmd.Flags().GetString("version")
		component, _ := cmd.Flags().GetString("component")
		online, _ := cmd.Flags().GetBool("online")

		if version == "" && component == "" {
			return fmt.Errorf("supply --version and/or --component (or --purge-cache)")
		}

		ctx, cancel := signalContext()
		defer cancel()

		fetcher, err := buildStandaloneFetcher(cmd, online)
		if err != nil {
			return err
		}

		advisories, err := fetcher.Fetch(ctx, cve.Query{
			Product:   "joomla",
			Version:   version,
			Component: component,
		})
		if err != nil {
			return err
		}

		// Filter to advisories that actually cover the version, when precise.
		if cve.IsVersionComplete(version) {
			var filtered []cve.Advisory
			for _, a := range advisories {
				if a.AffectsVersion(version) {
					filtered = append(filtered, a)
				}
			}
			advisories = filtered
		}

		if len(advisories) == 0 {
			fmt.Fprintln(stdout, "[-] No matching advisories found.")
			return nil
		}

		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "CVE\tCVSS\tSEVERITY\tSOURCE\tTITLE")
		fmt.Fprintln(w, "---\t----\t--------\t------\t-----")
		for _, a := range advisories {
			fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\t%s\n",
				a.ID, a.CVSS, a.SeverityLabel(), a.Source, truncateTitle(a.Title, 70))
		}
		if err := w.Flush(); err != nil {
			return err
		}

		fmt.Fprintf(stdout, "\n[+] %d advisories\n", len(advisories))
		return nil
	},
}

func buildStandaloneFetcher(cmd *cobra.Command, online bool) (cve.CVEFetcher, error) {
	offline := cve.NewOfflineFetcher(nil)
	if !online {
		return offline, nil
	}

	nvdKey, _ := cmd.Flags().GetString("nvd-api-key")
	ghToken, _ := cmd.Flags().GetString("github-token")
	if nvdKey == "" {
		nvdKey = os.Getenv("NVD_API_KEY")
	}
	if ghToken == "" {
		ghToken = os.Getenv("GITHUB_TOKEN")
	}
	cacheDir, _ := cmd.Flags().GetString("cache-dir")
	ttlHours, _ := cmd.Flags().GetInt("cache-ttl")

	providers := []cve.CVEFetcher{
		cve.NewNVDProvider(cve.WithNVDAPIKey(nvdKey)),
		cve.NewGitHubProvider(cve.WithGitHubToken(ghToken)),
	}

	opts := []cve.MultiFetcherOption{
		cve.WithOfflineSource(offline),
		cve.WithTimeout(45 * time.Second),
		cve.WithErrorHandler(func(provider string, err error) {
			fmt.Fprintf(cmd.ErrOrStderr(), "[!] %s: %v\n", provider, err)
		}),
	}

	if cache, err := cve.NewDiskCache(cacheDir, time.Duration(ttlHours)*time.Hour); err == nil {
		opts = append(opts, cve.WithCache(cache))
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "[!] CVE disk cache unavailable, using memory cache: %v\n", err)
		opts = append(opts, cve.WithCache(cve.NewMemoryCache(time.Duration(ttlHours)*time.Hour)))
	}

	return cve.NewMultiFetcher(providers, opts...), nil
}

func truncateTitle(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func init() {
	f := cveCmd.Flags()
	f.String("version", "", "Joomla version to look up, e.g. 3.9.4")
	f.String("component", "", "component to look up, e.g. com_fields")
	f.Bool("online", false, "query live CVE feeds (NVD + GitHub Advisory Database)")
	f.String("cache-dir", "", "CVE cache directory (default $HOME/.joomhound/cache/cve)")
	f.Int("cache-ttl", 24, "CVE cache freshness in hours")
	f.Bool("purge-cache", false, "delete all cached CVE data and exit")
	f.String("nvd-api-key", "", "NVD API key (or set NVD_API_KEY)")
	f.String("github-token", "", "GitHub token (or set GITHUB_TOKEN)")
}
