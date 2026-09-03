package commands

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the JoomHound version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("JoomHound %s (%s/%s, %s)\n",
			Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil
	},
}
