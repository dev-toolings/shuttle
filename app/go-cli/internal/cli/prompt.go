package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var stdinReader *bufio.Reader

func getStdinReader() *bufio.Reader {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	return stdinReader
}

// promptString asks a question and returns the answer. If empty, returns defaultVal.
func promptString(question string, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", question, defaultVal)
	} else {
		fmt.Printf("%s: ", question)
	}
	reader := getStdinReader()
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

// promptInt asks for an integer. Returns defaultVal if empty.
func promptInt(question string, defaultVal int) int {
	fmt.Printf("%s [%d]: ", question, defaultVal)
	reader := getStdinReader()
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		fmt.Printf("  Invalid number, using default %d\n", defaultVal)
		return defaultVal
	}
	return n
}
