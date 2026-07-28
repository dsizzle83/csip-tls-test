package bundle

// redact.go decides which parts of a recorded command line a bundle may carry.
//
// RunMeta.Command exists so a bundle can say what was asked of the device. That
// makes the bundle more useful and slightly more dangerous at the same time: a
// command line is where credentials live on this bench, and a bundle is a thing
// we hand to an assessor. The rule is therefore not "record the invocation" but
// "record the invocation minus the values nobody outside this room should see",
// and the rule has to be legible, because a redactor nobody can predict is one
// operators route around.
//
// Two shapes are covered:
//
//   - a flag whose NAME looks like a credential (-token, -api-key, -password),
//     in either `-flag value` or `-flag=value` form;
//   - a key=value argument whose KEY looks like a credential, which is how
//     -param carries per-procedure values and how a secret would arrive if one
//     ever did.
//
// What is deliberately NOT redacted matters as much. -gateway-ssh keeps its
// value: it is a host alias ("cc93"), it is the provenance of every narrative
// assertion sourced from gateway introspection, and blanking it would cost a
// reader the answer to "which device was introspected?" to protect nothing.
// -keylog likewise keeps its path: the secret is the FILE, which the bundle
// ships knowingly and warns about in REPORT.md — the path is provenance, and
// hiding it while shipping its contents would be theatre.

import (
	"regexp"
	"strings"
)

// Redacted replaces a value this package will not record. It is a fixed string
// rather than an empty one so a reader can tell "withheld" from "absent" — an
// argument that was passed and hidden is a different fact from one that was
// never given.
const Redacted = "[redacted]"

// secretFlagName matches flag names whose VALUES must not travel in a bundle.
var secretFlagName = regexp.MustCompile(`(?i)(secret|token|passw|password|credential|bearer|apikey|api[-_]?key|ssh|key)`)

// keptFlags are the names secretFlagName matches that are nevertheless recorded
// in full, each for a reason given in the file comment above. A flag is on this
// list only when its value is provenance rather than a credential.
var keptFlags = map[string]bool{
	"gateway-ssh": true,
	"keylog":      true,
}

// secretKey matches the KEY half of a key=value argument whose value must not
// travel.
var secretKey = regexp.MustCompile(`(?i)(secret|token|pass|key)`)

// SecretFlag reports whether a flag's value must be withheld. It is a variable
// so a binary with credential flags this package cannot know about can widen
// the rule at init:
//
//	prev := bundle.SecretFlag
//	bundle.SecretFlag = func(name string) bool { return name == "hsm-pin" || prev(name) }
//
// Narrowing it is possible too and is a decision to be made in the open: what
// this returns is exactly what does not appear in the evidence.
var SecretFlag = DefaultSecretFlag

// DefaultSecretFlag is the shipped rule. name arrives without its leading
// dashes.
func DefaultSecretFlag(name string) bool {
	if keptFlags[name] {
		return false
	}
	return secretFlagName.MatchString(name)
}

// SecretParamKey reports whether a key=value argument's value must be withheld.
// It is a variable for the same reason SecretFlag is.
var SecretParamKey = DefaultSecretParamKey

// DefaultSecretParamKey is the shipped rule for key=value arguments.
func DefaultSecretParamKey(key string) bool { return secretKey.MatchString(key) }

// RedactCommand returns argv with credential values replaced, leaving
// everything else — including every flag NAME, and the fact that a flag was
// given at all — verbatim.
//
// It returns a fresh slice; the caller's argv is not touched, because the
// process is normally still using it.
func RedactCommand(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	out := make([]string, 0, len(argv))
	redactNext := false
	for i, arg := range argv {
		if redactNext {
			redactNext = false
			// A flag followed by another flag took no value (a bool), so there
			// is nothing to withhold and the next argument is not ours.
			if !isFlag(arg) {
				out = append(out, Redacted)
				continue
			}
		}
		if i == 0 || !isFlag(arg) {
			out = append(out, redactPair(arg))
			continue
		}
		name, value, joined := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		switch {
		case !joined:
			// `-flag`: its value, if it takes one, is the next argument.
			redactNext = SecretFlag(name)
			out = append(out, arg)
		case SecretFlag(name):
			out = append(out, flagDashes(arg)+name+"="+Redacted)
		default:
			out = append(out, flagDashes(arg)+name+"="+redactPair(value))
		}
	}
	return out
}

// redactPair blanks the value of a bare key=value argument with a
// credential-shaped key, and returns anything else unchanged.
func redactPair(arg string) string {
	key, _, ok := strings.Cut(arg, "=")
	if !ok || key == "" || !SecretParamKey(key) {
		return arg
	}
	return key + "=" + Redacted
}

func isFlag(arg string) bool { return strings.HasPrefix(arg, "-") && arg != "-" && arg != "--" }

// flagDashes preserves whichever of -flag / --flag the operator typed, so the
// recorded line is the one they can paste back.
func flagDashes(arg string) string {
	if strings.HasPrefix(arg, "--") {
		return "--"
	}
	return "-"
}

// shellLine renders an argv as one pasteable line, quoting only what needs it.
func shellLine(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
