package main

import (
	"fmt"
	"os"

	"github.com/w41l3r/joomhound/cmd/joomhound/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
