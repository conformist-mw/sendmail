package main

import (
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want Options
	}{
		{
			name: "cron style invocation with -oi",
			argv: []string{"-oi", "-t", "user@host"},
			want: Options{ReadRecipients: true, Recipients: []string{"user@host"}},
		},
		{
			name: "attached values",
			argv: []string{"-FCronDaemon", "-froot@host", "user@host"},
			want: Options{
				SenderName:    "CronDaemon",
				SenderAddress: "root@host",
				Recipients:    []string{"user@host"},
			},
		},
		{
			name: "separate values",
			argv: []string{"-F", "Cron Daemon", "-f", "root@host", "user@host"},
			want: Options{
				SenderName:    "Cron Daemon",
				SenderAddress: "root@host",
				Recipients:    []string{"user@host"},
			},
		},
		{
			name: "options after recipients",
			argv: []string{"user@host", "-t"},
			want: Options{ReadRecipients: true, Recipients: []string{"user@host"}},
		},
		{
			name: "-r is an alias of -f",
			argv: []string{"-r", "root@host"},
			want: Options{SenderAddress: "root@host"},
		},
		{
			name: "exim style options are ignored",
			argv: []string{"-oem", "-odb", "-i", "-oi", "-bm", "user@host"},
			want: Options{Mode: "m", Recipients: []string{"user@host"}},
		},
		{
			name: "attached options never eat a recipient",
			argv: []string{"-o", "user@host"},
			want: Options{Recipients: []string{"user@host"}},
		},
		{
			name: "unknown options are ignored, not rejected",
			argv: []string{"-Z", "--nonsense", "user@host"},
			want: Options{Recipients: []string{"user@host"}},
		},
		{
			name: "mailq mode",
			argv: []string{"-bp"},
			want: Options{Mode: "p"},
		},
		{
			name: "long options with two dashes",
			argv: []string{"--send-file", "/var/log/syslog"},
			want: Options{SendFile: "/var/log/syslog"},
		},
		{
			name: "long options with one dash stay supported",
			argv: []string{"-send-file", "/var/log/syslog"},
			want: Options{SendFile: "/var/log/syslog"},
		},
		{
			name: "long option with equals sign",
			argv: []string{"--send-file=/var/log/syslog", "--get-updates"},
			want: Options{SendFile: "/var/log/syslog", GetUpdates: true},
		},
		{
			name: "double dash ends option parsing",
			argv: []string{"--", "-weird@host"},
			want: Options{Recipients: []string{"-weird@host"}},
		},
		{
			name: "no arguments",
			argv: nil,
			want: Options{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseArgs(tc.argv)
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("ParseArgs(%q)\n got: %+v\nwant: %+v", tc.argv, *got, tc.want)
			}
		})
	}
}
