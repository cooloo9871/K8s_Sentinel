package registry

import (
	"fmt"
	"regexp"
	"strings"
)

// filter is one "repository[:tag]" pattern.
type filter struct {
	repo string
	tag  string // "*" when the filter names no tag
}

func parseFilter(s string) (filter, error) {
	f := filter{repo: s, tag: "*"}
	// A colon after the last slash separates the tag; one before it would be a
	// port, which does not belong in a filter anyway.
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		f.repo, f.tag = s[:i], s[i+1:]
	}
	f.repo = strings.Trim(f.repo, "/")
	if f.repo == "" || f.tag == "" || strings.ContainsAny(s, " \t@") {
		return filter{}, fmt.Errorf("filter %q: expected repository or repository:tag, with * as a wildcard", s)
	}
	return f, nil
}

// matchGlob reports whether s matches a pattern where * stands for any run of
// characters, slashes included: library/* covers library/a and library/a/b.
func matchGlob(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	ok, _ := regexp.MatchString("^"+strings.Join(parts, ".*")+"$", s)
	return ok
}
