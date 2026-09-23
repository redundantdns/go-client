package redundantdns

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The functions below mirror the server's canonical forms (the platform's
// dns-core normalization) so that clients can compare what they sent with
// what the API stores: the server lowercases names, adds trailing dots to
// hostnames, compresses IPv6, re-quotes TXT strings and sorts values.
// Internationalized names are not converted to punycode here: send them
// already in ASCII form.

const txtChunkSize = 255

var (
	digitsRegex = regexp.MustCompile(`^[0-9]+$`)
	caaRegex    = regexp.MustCompile(`^(\d+)\s+([A-Za-z0-9]+)\s+(.+)$`)
)

// NormalizeZoneName trims, lowercases and strips the trailing dot.
func NormalizeZoneName(name string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
}

// NormalizeRecordName returns the canonical relative name: "", "@", the
// zone name and the zone FQDN become "@"; "www.example.com." becomes "www"
// in zone example.com. With an empty zoneName the name is only trimmed and
// lowercased.
func NormalizeRecordName(zoneName, name string) string {
	zone := NormalizeZoneName(zoneName)
	raw := strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
	if raw == "" || raw == "@" || (zone != "" && raw == zone) {
		return "@"
	}
	if zone != "" && strings.HasSuffix(raw, "."+zone) {
		return strings.TrimSuffix(raw, "."+zone)
	}
	return raw
}

// NormalizeRecordValues returns the canonical values of one record set:
// each value normalized for its type, empty values and duplicates removed,
// sorted. It is the form the API stores and returns.
func NormalizeRecordValues(recordType string, values []string) []string {
	upper := strings.ToUpper(strings.TrimSpace(recordType))
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeValue(upper, value)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	slices.Sort(out)
	return out
}

// EqualRecordValues reports whether two value lists are the same record
// data once normalized (order and formatting ignored).
func EqualRecordValues(recordType string, left, right []string) bool {
	return slices.Equal(NormalizeRecordValues(recordType, left), NormalizeRecordValues(recordType, right))
}

func normalizeValue(recordType, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	switch recordType {
	case "CNAME", "NS", "PTR":
		return normalizeHostname(trimmed)
	case "A":
		return normalizeIPv4(trimmed)
	case "AAAA":
		return normalizeIPv6(trimmed)
	case "MX":
		return normalizeMX(trimmed)
	case "SRV":
		return normalizeSRV(trimmed)
	case "CAA":
		return normalizeCAA(trimmed)
	case "TXT":
		return normalizeTXT(trimmed)
	default:
		return trimmed
	}
}

func normalizeHostname(value string) string {
	host := strings.TrimRight(strings.ToLower(value), ".")
	if host == "" {
		return "."
	}
	return host + "."
}

func normalizeIPv4(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return value
	}
	out := make([]string, 4)
	for index, part := range parts {
		if len(part) < 1 || len(part) > 3 || !digitsRegex.MatchString(part) {
			return value
		}
		number, _ := strconv.Atoi(part)
		out[index] = strconv.Itoa(number)
	}
	return strings.Join(out, ".")
}

func normalizeIPv6(value string) string {
	lower := strings.ToLower(value)
	addr, err := netip.ParseAddr(lower)
	if err != nil || !addr.Is6() {
		return lower
	}
	return addr.String()
}

func normalizeMX(value string) string {
	fields := strings.Fields(value)
	if len(fields) != 2 || !digitsRegex.MatchString(fields[0]) {
		return value
	}
	priority, _ := strconv.Atoi(fields[0])
	return strconv.Itoa(priority) + " " + normalizeHostname(fields[1])
}

func normalizeSRV(value string) string {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return value
	}
	numbers := make([]string, 3)
	for index := range 3 {
		if !digitsRegex.MatchString(fields[index]) {
			return value
		}
		number, _ := strconv.Atoi(fields[index])
		numbers[index] = strconv.Itoa(number)
	}
	return strings.Join(numbers, " ") + " " + normalizeHostname(fields[3])
}

func normalizeCAA(value string) string {
	match := caaRegex.FindStringSubmatch(value)
	if match == nil {
		return value
	}
	flags, _ := strconv.Atoi(match[1])
	content := strings.Join(parseTXTStrings(match[3]), "")
	return strconv.Itoa(flags) + " " + strings.ToLower(match[2]) + ` "` + escapeTXT(content) + `"`
}

// normalizeTXT concatenates the character-strings and re-splits them into
// quoted 255-char chunks: `v=spf1 -all` and `"v=spf1" " -all"` both become
// `"v=spf1 -all"`.
func normalizeTXT(value string) string {
	content := strings.Join(parseTXTStrings(value), "")
	var chunks []string
	for start := 0; start < len(content); start += txtChunkSize {
		end := min(start+txtChunkSize, len(content))
		chunks = append(chunks, `"`+escapeTXT(content[start:end])+`"`)
	}
	if len(chunks) == 0 {
		chunks = []string{`""`}
	}
	return strings.Join(chunks, " ")
}

func escapeTXT(content string) string {
	return strings.ReplaceAll(strings.ReplaceAll(content, `\`, `\\`), `"`, `\"`)
}

// parseTXTStrings splits TXT rdata into its character-strings; unquoted
// input is one string.
func parseTXTStrings(value string) []string {
	text := strings.TrimSpace(value)
	if !strings.HasPrefix(text, `"`) {
		return []string{text}
	}
	var strs []string
	var current *strings.Builder
	runes := []rune(text)
	for index := 0; index < len(runes); index++ {
		char := runes[index]
		switch {
		case current == nil:
			if char == '"' {
				current = &strings.Builder{}
			}
		case char == '\\' && index+1 < len(runes):
			current.WriteRune(runes[index+1])
			index++
		case char == '"':
			strs = append(strs, current.String())
			current = nil
		default:
			current.WriteRune(char)
		}
	}
	if current != nil {
		strs = append(strs, current.String())
	}
	return strs
}
