// Package glob implements the wildcard matching used by IAM policy elements.
//
// IAM patterns support two wildcards: '*' matches any sequence of characters
// (including the empty sequence) and '?' matches exactly one character.
// There is no escape syntax in IAM itself; policy variables ${*} and ${?}
// produce literal '*' and '?' characters. This package represents those
// literals with the private-use runes LiteralStar and LiteralQuestion so a
// substituted pattern can carry them without them acting as wildcards.
//
// Complexity: Match runs the classic greedy two-pointer algorithm with a
// single backtrack point: O(len(p)+len(s)) on typical inputs and
// O(len(p)*len(s)) in the worst case, with O(len(p)+len(s)) space for the
// rune conversion. Subsumes is a dynamic program over both patterns:
// O(len(g)*len(s)) time and O(len(s)) space.
package glob

import (
	"strings"
	"unicode/utf8"
)

const (
	// LiteralStar is the escaped form of a literal '*' inside a pattern.
	LiteralStar = ''
	// LiteralQuestion is the escaped form of a literal '?' inside a pattern.
	LiteralQuestion = ''
)

// Escape converts a raw string into a pattern that matches only itself,
// replacing '*' and '?' with their literal escapes.
func Escape(s string) string {
	if !strings.ContainsAny(s, "*?") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '*':
			b.WriteRune(LiteralStar)
		case '?':
			b.WriteRune(LiteralQuestion)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Unescape converts literal escapes back into their plain characters. It is
// used when a pattern is compared for equality rather than matched.
func Unescape(p string) string {
	if !strings.ContainsRune(p, LiteralStar) && !strings.ContainsRune(p, LiteralQuestion) {
		return p
	}
	return strings.NewReplacer(string(LiteralStar), "*", string(LiteralQuestion), "?").Replace(p)
}

// HasWildcard reports whether p contains an unescaped '*' or '?'.
func HasWildcard(p string) bool {
	return strings.ContainsAny(p, "*?")
}

// literal maps an escaped literal rune back to the character it stands for.
func literal(r rune) rune {
	switch r {
	case LiteralStar:
		return '*'
	case LiteralQuestion:
		return '?'
	}
	return r
}

func toRunes(s string, fold bool) []rune {
	if fold {
		s = strings.ToLower(s)
	}
	out := make([]rune, 0, utf8.RuneCountInString(s))
	for _, r := range s {
		out = append(out, r)
	}
	return out
}

// Match reports whether s matches pattern p (case-sensitive).
func Match(p, s string) bool {
	if p == "*" {
		return true
	}
	if !HasWildcard(p) && !strings.ContainsRune(p, LiteralStar) && !strings.ContainsRune(p, LiteralQuestion) {
		return p == s
	}
	return matchRunes(toRunes(p, false), toRunes(s, false))
}

// MatchFold reports whether s matches pattern p, ignoring case. IAM action
// names are matched case-insensitively.
func MatchFold(p, s string) bool {
	if p == "*" {
		return true
	}
	if !HasWildcard(p) && !strings.ContainsRune(p, LiteralStar) && !strings.ContainsRune(p, LiteralQuestion) {
		return strings.EqualFold(p, s)
	}
	return matchRunes(toRunes(p, true), toRunes(s, true))
}

func matchRunes(p, s []rune) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && (p[pi] == '?' || literal(p[pi]) == s[si]):
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// Subsumes reports whether every string matched by pattern specific is also
// matched by pattern general (case-sensitive). The check is sound but not
// complete: a true result is a proof of inclusion; a false result means
// inclusion could not be established by token alignment. The generator only
// relies on true results, so incompleteness can cost precision, never safety.
func Subsumes(general, specific string) bool {
	if general == "*" {
		return true
	}
	return subsumesRunes(toRunes(general, false), toRunes(specific, false))
}

// SubsumesFold is Subsumes with case-insensitive comparison of literals.
func SubsumesFold(general, specific string) bool {
	if general == "*" {
		return true
	}
	return subsumesRunes(toRunes(general, true), toRunes(specific, true))
}

// subsumesRunes computes cover[i][j] = "g[i:] covers s[j:]" bottom-up with a
// rolling row. A '*' in g may absorb any token of s (including '*'); a '?' in
// g absorbs exactly one non-'*' token; a literal in g must align with an
// identical literal in s.
func subsumesRunes(g, s []rune) bool {
	n := len(s)
	next := make([]bool, n+1) // row i+1
	cur := make([]bool, n+1)  // row i
	next[n] = true            // empty g covers empty s only
	for i := len(g) - 1; i >= 0; i-- {
		switch g[i] {
		case '*':
			cur[n] = next[n]
			for j := n - 1; j >= 0; j-- {
				cur[j] = next[j] || cur[j+1]
			}
		case '?':
			cur[n] = false
			for j := n - 1; j >= 0; j-- {
				cur[j] = s[j] != '*' && next[j+1]
			}
		default:
			cur[n] = false
			want := literal(g[i])
			for j := n - 1; j >= 0; j-- {
				tok := s[j]
				cur[j] = tok != '*' && tok != '?' && literal(tok) == want && next[j+1]
			}
		}
		next, cur = cur, next
	}
	return next[0]
}
