package ers

import (
	"regexp"
	"sort"
	"strings"

	"github.com/mix3/tlds-go"
)

type option struct {
	exact     bool
	strict    bool
	gmail     bool
	utf8      bool
	localhost bool
	ipv4      bool
	ipv6      bool
	tlds      []string
}

type Option func(*option)

func Exact(v bool) Option {
	return func(u *option) {
		u.exact = v
	}
}

func Strict(v bool) Option {
	return func(u *option) {
		u.strict = v
	}
}

func Gmail(v bool) Option {
	return func(u *option) {
		u.gmail = v
	}
}

func Utf8(v bool) Option {
	return func(u *option) {
		u.utf8 = v
	}
}

func Localhost(v bool) Option {
	return func(u *option) {
		u.localhost = v
	}
}

func IPv4(v bool) Option {
	return func(u *option) {
		u.ipv4 = v
	}
}

func IPv6(v bool) Option {
	return func(u *option) {
		u.ipv6 = v
	}
}

func Tlds(v []string) Option {
	return func(u *option) {
		u.tlds = v
	}
}

var (
	v4    = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}"
	v6seg = "[a-fA-F\\d]{1,4}"

	replacer = strings.NewReplacer(
		"\\u00a1", "\\x{00a1}",
		"\\uffff", "\\x{ffff}",
		"\\u00A0", "\\x{00A0}",
		"\\uD7FF", "\\x{D7FF}",
		"\\uF900", "\\x{F900}",
		"\\uFDCF", "\\x{FDCF}",
		"\\uFDF0", "\\x{FDF0}",
		"\\uFFEF", "\\x{FFEF}",
		"${v4}", v4,
		"${v6seg}", v6seg,
	)
)

func New(opts ...Option) (*regexp.Regexp, error) {
	opt := &option{
		gmail:     true,
		utf8:      true,
		localhost: true,
		ipv4:      true,
		tlds:      tlds.List(),
	}
	for _, f := range opts {
		f(opt)
	}

	host := "(?:(?:[a-z\\u00a1-\\uffff0-9][-_]*)*[a-z\\u00a1-\\uffff0-9]+)"
	domain := "(?:\\.(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)*"

	tld := "(?:\\."
	if opt.strict {
		tld += "(?:[a-z\\u00a1-\\uffff]{2,})"
	} else {
		sort.SliceStable(opt.tlds, func(i, j int) bool {
			a, b := len([]rune(opt.tlds[i])), len([]rune(opt.tlds[j]))
			return b < a // desc
		})
		tld += "(?:" + strings.Join(opt.tlds, "|") + ")"
	}
	tld += ")"

	var emailUserPart string
	switch {
	case opt.gmail:
		emailUserPart = "[^\\W_](?:[\\w\\.\\+]+)"
	case opt.utf8:
		emailUserPart = "[^\\W_](?:[a-z\\d!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~\\u00A0-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFEF]+)"
	default:
		emailUserPart = "[^\\W_](?:[a-z\\d!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]+)"
	}

	regex := "(?:" + emailUserPart + "@(?:"
	if opt.localhost {
		regex += "localhost|"
	}
	if opt.ipv4 {
		regex += v4 + "|"
	}
	if opt.ipv6 {
		reg := strings.Join([]string{
			"(?:",
			"(?:${v6seg}:){7}(?:${v6seg}|:)|",        // 1:2:3:4:5:6:7::  1:2:3:4:5:6:7:8
			"(?:${v6seg}:){6}(?:${v4}|:${v6seg}|:)|", // 1:2:3:4:5:6::    1:2:3:4:5:6::8   1:2:3:4:5:6::8  1:2:3:4:5:6::1.2.3.4
			"(?:${v6seg}:){5}(?::${v4}|(?::${v6seg}){1,2}|:)|",                   // 1:2:3:4:5::      1:2:3:4:5::7:8   1:2:3:4:5::8    1:2:3:4:5::7:1.2.3.4
			"(?:${v6seg}:){4}(?:(?::${v6seg}){0,1}:${v4}|(?::${v6seg}){1,3}|:)|", // 1:2:3:4::        1:2:3:4::6:7:8   1:2:3:4::8      1:2:3:4::6:7:1.2.3.4
			"(?:${v6seg}:){3}(?:(?::${v6seg}){0,2}:${v4}|(?::${v6seg}){1,4}|:)|", // 1:2:3::          1:2:3::5:6:7:8   1:2:3::8        1:2:3::5:6:7:1.2.3.4
			"(?:${v6seg}:){2}(?:(?::${v6seg}){0,3}:${v4}|(?::${v6seg}){1,5}|:)|", // 1:2::            1:2::4:5:6:7:8   1:2::8          1:2::4:5:6:7:1.2.3.4
			"(?:${v6seg}:){1}(?:(?::${v6seg}){0,4}:${v4}|(?::${v6seg}){1,6}|:)|", // 1::              1::3:4:5:6:7:8   1::8            1::3:4:5:6:7:1.2.3.4
			"(?::(?:(?::${v6seg}){0,5}:${v4}|(?::${v6seg}){1,7}|:))",             // ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8  ::8             ::1.2.3.4
			")(?:%[0-9a-zA-Z]{1,})?", // %eth0            %1
		}, "")
		regex += reg + "|"
	}

	regex += host + domain + tld + "))"

	if opt.exact {
		regex = "(?i)(?:^" + regex + "$)"
	} else {
		regex = "(?i)" + regex
	}

	regex = replacer.Replace(regex)

	return regexp.Compile(regex)
}
