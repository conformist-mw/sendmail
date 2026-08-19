package main

import "strings"

// Options holds everything the command line can ask for.
type Options struct {
	SenderName     string   // -F
	SenderAddress  string   // -f, -r
	ReadRecipients bool     // -t
	SendFile       string   // --send-file
	GetUpdates     bool     // --get-updates
	Help           bool     // --help
	Version        bool     // --version
	Mode           string   // -b<x>, the operation mode
	Recipients     []string // everything that is not an option
}

// Callers of /usr/sbin/sendmail pass a wide and inconsistent set of options:
// values may be attached to the letter (-froot@host) or separate (-f root@host),
// and options may appear after recipients. Anything unrecognised is ignored
// rather than rejected — refusing a message because of an unknown option would
// lose mail that a real MTA would have delivered.
var (
	// Options whose value may be attached or supplied as the next argument.
	shortWithValue = map[byte]bool{
		'f': true, 'r': true, 'F': true, 'C': true, 'h': true, 'L': true,
		'M': true, 'N': true, 'R': true, 'V': true, 'X': true, 'B': true,
		'p': true, 'O': true,
	}
	// Options that never take a value.
	shortNoValue = map[byte]bool{
		't': true, 'i': true, 'v': true, 'n': true, 's': true, 'm': true,
		'E': true, 'G': true, 'U': true,
	}
	// Options whose value is always attached (-oi, -bm, -q30m), so the next
	// argument must never be consumed — it is usually a recipient.
	shortAttached = map[byte]bool{
		'o': true, 'b': true, 'd': true, 'q': true, 'e': true, 'A': true,
	}
)

// longNames are this program's own options. They are accepted with one or two
// leading dashes because earlier versions were parsed by Go's flag package.
var longNames = map[string]bool{
	"send-file": true, "get-updates": true, "help": true, "version": true,
}

// ParseArgs interprets a sendmail-style command line.
func ParseArgs(argv []string) *Options {
	opts := &Options{}

	for i := 0; i < len(argv); i++ {
		arg := argv[i]

		if arg == "--" {
			opts.Recipients = append(opts.Recipients, argv[i+1:]...)
			break
		}
		if arg == "" || arg == "-" || arg[0] != '-' {
			opts.Recipients = append(opts.Recipients, arg)
			continue
		}

		name, value, hasValue := splitLongOption(arg)
		if longNames[name] {
			switch name {
			case "send-file":
				if !hasValue && i+1 < len(argv) {
					value, i = argv[i+1], i+1
				}
				opts.SendFile = value
			case "get-updates":
				opts.GetUpdates = true
			case "help":
				opts.Help = true
			case "version":
				opts.Version = true
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			continue // unknown long option
		}

		letter, rest := arg[1], arg[2:]
		switch {
		case shortWithValue[letter]:
			if rest == "" && i+1 < len(argv) {
				rest, i = argv[i+1], i+1
			}
			switch letter {
			case 'f', 'r':
				opts.SenderAddress = rest
			case 'F':
				opts.SenderName = rest
			}
		case shortNoValue[letter]:
			if letter == 't' {
				opts.ReadRecipients = true
			}
		case shortAttached[letter]:
			if letter == 'b' {
				opts.Mode = rest
			}
		}
	}

	return opts
}

// splitLongOption strips leading dashes and splits an --option=value pair.
func splitLongOption(arg string) (name, value string, hasValue bool) {
	name = strings.TrimLeft(arg, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		return name[:i], name[i+1:], true
	}
	return name, "", false
}
