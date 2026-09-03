package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// maxWordlistLineBytes bounds a single wordlist line. bufio.Scanner's default
// is 64KB and it returns bufio.ErrTooLong on longer lines, which silently
// truncated wordlists containing a very long entry.
const maxWordlistLineBytes = 1 << 20 // 1 MiB

// LoadWordlist loads a wordlist from a file, one word per line. Blank lines
// and '#' comments are skipped and duplicates are removed, so a wordlist with
// repeated entries does not multiply the request count.
func LoadWordlist(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist %s: %w", filepath, err)
	}
	defer file.Close()

	var words []string
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxWordlistLineBytes)

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if _, dup := seen[word]; dup {
			continue
		}
		seen[word] = struct{}{}
		words = append(words, word)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist %s: %w", filepath, err)
	}

	return words, nil
}

// DefaultUsernames is an alias for GetCommonUsernames, matching the naming
// used by the CLI layer.
func DefaultUsernames() []string { return GetCommonUsernames() }

// DefaultPasswords is an alias for GetCommonPasswords.
func DefaultPasswords() []string { return GetCommonPasswords() }

// LoadMultipleWordlists loads words from multiple wordlist files
func LoadMultipleWordlists(filepaths []string) ([]string, error) {
	var allWords []string
	seenWords := make(map[string]bool)

	for _, filepath := range filepaths {
		words, err := LoadWordlist(filepath)
		if err != nil {
			return nil, err
		}

		for _, word := range words {
			if !seenWords[word] {
				allWords = append(allWords, word)
				seenWords[word] = true
			}
		}
	}

	return allWords, nil
}

// GetCommonUsernames returns a list of common usernames if no wordlist is provided
func GetCommonUsernames() []string {
	return []string{
		"admin",
		"administrator",
		"root",
		"test",
		"guest",
		"user",
		"www-data",
		"webmaster",
		"postmaster",
		"support",
		"joomla",
		"manager",
		"editor",
		"publisher",
		"author",
	}
}

// GetCommonPasswords returns a list of common passwords if no wordlist is provided
func GetCommonPasswords() []string {
	return []string{
		"password",
		"123456",
		"12345678",
		"qwerty",
		"abc123",
		"monkey",
		"1234567",
		"letmein",
		"trustno1",
		"dragon",
		"baseball",
		"iloveyou",
		"master",
		"sunshine",
		"ashley",
		"bailey",
		"shadow",
		"superman",
		"qazwsx",
		"michael",
		"football",
		"admin",
		"root",
		"toor",
		"joomla",
	}
}
