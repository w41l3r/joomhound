package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadWordlist loads a wordlist from a file, one word per line
func LoadWordlist(filepath string) ([]string, error) {
	var words []string

	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist %s: %w", filepath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}

	return words, nil
}

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
