// Value-token matching: the `val`/`nval` conditions a binding places on a call's literal
// arguments, and the caches that keep them off the hot path.

package bindings

import (
	"strconv"
	"strings"
	"unsafe"

	"github.com/vyprai/vyql/internal/usg"
)

func valContains(tokens, sub string) bool {
	return valContainsLower(lowerString(tokens), sub)
}

func valContainsLower(lowerTokens, sub string) bool {
	return strings.Contains(lowerTokens, lowerString(sub))
}

func lowerString(s string) string {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 0x80 {
			return strings.ToLower(s)
		}
		if ch >= 'A' && ch <= 'Z' {
			for j := i + 1; j < len(s); j++ {
				if s[j] >= 0x80 {
					return strings.ToLower(s)
				}
			}
			b := []byte(s)
			b[i] = ch + ('a' - 'A')
			for j := i + 1; j < len(b); j++ {
				ch = b[j]
				if ch >= 'A' && ch <= 'Z' {
					b[j] = ch + ('a' - 'A')
				}
			}
			return unsafe.String(unsafe.SliceData(b), len(b))
		}
	}
	return s
}

func valContainsLowerNeedle(lowerTokens, lowerSub string) bool {
	return strings.Contains(lowerTokens, lowerSub)
}

func valContainsFoldedNeedle(tokens, lowerSub string) bool {
	if lowerSub == "" {
		return true
	}
	if len(lowerSub) > len(tokens) {
		return false
	}
	for i := 0; i < len(lowerSub); i++ {
		if lowerSub[i] >= 0x80 {
			return strings.Contains(lowerString(tokens), lowerSub)
		}
	}
	first := lowerSub[0]
	limit := len(tokens) - len(lowerSub)
	for i := 0; i <= limit; i++ {
		ch := tokens[i]
		if ch >= 0x80 {
			return strings.Contains(lowerString(tokens), lowerSub)
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch != first {
			continue
		}
		match := true
		for j := 1; j < len(lowerSub); j++ {
			ch = tokens[i+j]
			if ch >= 0x80 {
				return strings.Contains(lowerString(tokens), lowerSub)
			}
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			if ch != lowerSub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// valConds reports whether every `val` substring is present (AND) and every
// `nval` substring is absent among the value tokens. Empty lists pass.

func valConds(tokens string, vals, nvals []string) bool {
	return valCondsLower(lowerString(tokens), vals, nvals)
}

func valCondsLower(lowerTokens string, vals, nvals []string) bool {
	for _, v := range vals {
		if !valContainsLower(lowerTokens, v) {
			return false
		}
	}
	for _, nv := range nvals {
		if valContainsLower(lowerTokens, nv) {
			return false
		}
	}
	return true
}

func valCondsLowerNeedles(lowerTokens string, valsLower, nvalsLower []string) bool {
	for _, v := range valsLower {
		if !valContainsLowerNeedle(lowerTokens, v) {
			return false
		}
	}
	for _, nv := range nvalsLower {
		if valContainsLowerNeedle(lowerTokens, nv) {
			return false
		}
	}
	return true
}

func valCondsFoldedNeedles(tokens string, valsLower, nvalsLower []string) bool {
	for _, v := range valsLower {
		if !valContainsFoldedNeedle(tokens, v) {
			return false
		}
	}
	for _, nv := range nvalsLower {
		if valContainsFoldedNeedle(tokens, nv) {
			return false
		}
	}
	return true
}

type valueTokenCache struct {
	shared             *flagMatchIndex
	sinkRaw            map[string]string
	directSinkSegments map[string]directSinkSegments
	directRawContains  map[string]bool
}

func newValueTokenCache(s usg.Store) *valueTokenCache {
	if s == nil {
		return &valueTokenCache{}
	}
	return &valueTokenCache{shared: sharedFlagIndex(s)}
}

func (c *valueTokenCache) sinkValueRaw(s usg.Store, idx *flowTokenIndex, call usg.Node, argIndex int, includeFlow bool) string {
	if call.ID != "" {
		if c.sinkRaw == nil {
			c.sinkRaw = map[string]string{}
		}
		key := call.ID + "\x00" + strconv.Itoa(argIndex)
		if includeFlow {
			key += "\x00flow"
		} else {
			key += "\x00direct"
		}
		if raw, ok := c.sinkRaw[key]; ok {
			return raw
		}
		raw := buildSinkValueRaw(s, idx, call, argIndex, includeFlow)
		c.sinkRaw[key] = raw
		return raw
	}
	return buildSinkValueRaw(s, idx, call, argIndex, includeFlow)
}

func buildSinkValueRaw(s usg.Store, idx *flowTokenIndex, call usg.Node, argIndex int, includeFlow bool) string {
	// The parts are collected first and joined once. An unsized Builder grows by doubling,
	// and the flowing-token strings this concatenates are large on generated code — the
	// doubling copies alone were a third of all allocation on such a corpus. Join allocates
	// the exact final size; the parts slice is a few pointers against that.
	var parts []string
	addRaw := func(text string) {
		if text != "" {
			parts = append(parts, text)
		}
	}
	addRaw(call.Prop("str_args"))
	addArg := func(arg string) {
		if arg == "" {
			return
		}
		if n, ok, err := s.GetNode(arg); err == nil && ok {
			addRaw(n.Prop("str_args"))
			if includeFlow {
				addRaw(flowingStringTokens(s, idx, n.ID, n.Prop("str_args")))
			}
		}
	}
	if argIndex >= 0 {
		addArg(call.Prop(usg.ArgPropKey(argIndex)))
	} else {
		for ai := 0; ; ai++ {
			arg := call.Prop(usg.ArgPropKey(ai))
			if arg == "" {
				break
			}
			addArg(arg)
		}
	}
	if includeFlow {
		addRaw(flowingStringTokens(s, idx, call.ID, call.Prop("str_args")))
	}
	if len(parts) == 1 {
		return parts[0] // no separator, no copy
	}
	return strings.Join(parts, "\x00")
}

type directSinkSegments struct {
	raw   []string
	nodes []usg.Node
}

func (c *valueTokenCache) directSegments(s usg.Store, call usg.Node, argIndex int) directSinkSegments {
	key := directSinkSegmentKey(call, argIndex)
	if key != "" {
		if c.directSinkSegments == nil {
			c.directSinkSegments = map[string]directSinkSegments{}
		}
		if segs, ok := c.directSinkSegments[key]; ok {
			return segs
		}
	}
	segs := directSinkSegments{}
	segs.addRaw(call.Prop("str_args"))
	addArg := func(arg string) {
		if arg == "" {
			return
		}
		if n, ok, err := s.GetNode(arg); err == nil && ok {
			if text := n.Prop("str_args"); text != "" {
				if segs.addRaw(text) {
					segs.nodes = append(segs.nodes, n)
				}
			}
		}
	}
	if argIndex >= 0 {
		addArg(call.Prop(usg.ArgPropKey(argIndex)))
	} else {
		for ai := 0; ; ai++ {
			arg := call.Prop(usg.ArgPropKey(ai))
			if arg == "" {
				break
			}
			addArg(arg)
		}
	}
	if key != "" {
		c.directSinkSegments[key] = segs
	}
	return segs
}

func (segs *directSinkSegments) addRaw(text string) bool {
	if text == "" {
		return false
	}
	for _, existing := range segs.raw {
		if rawSegmentCoveredBy(existing, text) {
			return false
		}
	}
	segs.raw = append(segs.raw, text)
	return true
}

func rawSegmentCoveredBy(existing, text string) bool {
	if existing == text {
		return true
	}
	if text == "" || len(text) > len(existing) {
		return false
	}
	for start := 0; start <= len(existing)-len(text); {
		rel := strings.Index(existing[start:], text)
		if rel < 0 {
			return false
		}
		pos := start + rel
		end := pos + len(text)
		if (pos == 0 || existing[pos-1] == 0) && (end == len(existing) || existing[end] == 0) {
			return true
		}
		start = pos + 1
	}
	return false
}

func directSinkSegmentKey(call usg.Node, argIndex int) string {
	if call.ID == "" {
		return ""
	}
	return call.ID + "\x00" + strconv.Itoa(argIndex)
}

func (c *valueTokenCache) directRawContainsFolded(call usg.Node, argIndex int, rawSegments []string, needle string) bool {
	key := directSinkSegmentKey(call, argIndex)
	if key == "" {
		return rawSegmentsContainFolded(rawSegments, needle)
	}
	cacheKey := key + "\x00raw\x00" + needle
	if c.directRawContains == nil {
		c.directRawContains = map[string]bool{}
	}
	if hit, ok := c.directRawContains[cacheKey]; ok {
		return hit
	}
	hit := rawSegmentsContainFolded(rawSegments, needle)
	c.directRawContains[cacheKey] = hit
	return hit
}

func lowerStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = lowerString(v)
	}
	return out
}

func (pred flagPredicate) lowerValues() []string {
	if len(pred.valuesLower) == len(pred.Values) {
		return pred.valuesLower
	}
	return lowerStrings(pred.Values)
}

func valCondsForNode(s usg.Store, idx *flowTokenIndex, n usg.Node, vals, nvals []string) bool {
	if len(vals) == 0 && len(nvals) == 0 {
		return true
	}
	direct := n.Prop("str_args")
	lowerDirect := lowerString(direct)
	if valCondsLower(lowerDirect, vals, nvals) {
		return true
	}
	for _, nv := range nvals {
		if valContainsLower(lowerDirect, nv) {
			return false
		}
	}
	if strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
		return false
	}
	if len(vals) == 0 {
		return false
	}
	return valConds(flowingStringTokens(s, idx, n.ID, direct), vals, nvals)
}

func valCondsDirectForNodeCached(cache *valueTokenCache, n usg.Node, valsLower, nvalsLower []string) bool {
	if len(valsLower) == 0 && len(nvalsLower) == 0 {
		return true
	}
	if len(valsLower) > 0 && strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
		if present, ok := rawSegmentsContainStructuredContextNeedle([]string{n.Prop("str_args")}, valsLower[0]); ok && !present {
			return false
		}
	}
	return valCondsFoldedNeedles(nodeDirectValueTokens(n), valsLower, nvalsLower)
}

func valCondsForSinkCached(s usg.Store, idx *flowTokenIndex, cache *valueTokenCache, call usg.Node, sk sinkSpec, valsLower, nvalsLower []string) bool {
	if len(valsLower) == 0 && len(nvalsLower) == 0 {
		return true
	}
	if len(valsLower) > 0 && strings.HasPrefix(call.Prop("callee_path"), "analysis.function.context.") {
		return valCondsForSinkDirectSegments(s, cache, call, sk.ArgIndex, valsLower, nvalsLower)
	}
	if functionReturnDecoratorAbsent(s, cache, call, sk.ArgIndex, valsLower) {
		return false
	}
	return valCondsFoldedNeedles(cache.sinkValueRaw(s, idx, call, sk.ArgIndex, len(valsLower) > 0), valsLower, nvalsLower)
}

func valCondsForSinkDirectSegments(s usg.Store, cache *valueTokenCache, call usg.Node, argIndex int, valsLower, nvalsLower []string) bool {
	direct := cache.directSegments(s, call, argIndex)
	if len(valsLower) > 0 {
		if present, ok := rawSegmentsContainStructuredContextNeedle(direct.raw, valsLower[0]); ok {
			if !present {
				return false
			}
		} else if shouldFoldedDirectPrecheck(valsLower, nvalsLower) &&
			!cache.directRawContainsFolded(call, argIndex, direct.raw, valsLower[0]) {
			return false
		}
		for _, v := range valsLower[1:] {
			if shouldFoldedDirectPrecheckValue(v) && !cache.directRawContainsFolded(call, argIndex, direct.raw, v) {
				return false
			}
		}
	}

	contains := func(needle string) bool {
		return cache.directRawContainsFolded(call, argIndex, direct.raw, needle)
	}
	for _, v := range valsLower {
		if !contains(v) {
			return false
		}
	}
	for _, nv := range nvalsLower {
		if contains(nv) {
			return false
		}
	}
	return true
}

func shouldFoldedDirectPrecheck(valsLower, _ []string) bool {
	if len(valsLower) == 0 {
		return false
	}
	first := valsLower[0]
	return shouldFoldedDirectPrecheckValue(first)
}

func shouldFoldedDirectPrecheckValue(lowerNeedle string) bool {
	return strings.HasSuffix(lowerNeedle, ":") ||
		len(lowerNeedle) >= 16 ||
		(strings.HasPrefix(lowerNeedle, "<") && len(lowerNeedle) >= 4)
}

func rawSegmentsContainStructuredContextNeedle(segments []string, lowerNeedle string) (bool, bool) {
	prefix, ok := structuredContextNeedlePrefix(lowerNeedle)
	if !ok {
		return false, false
	}
	for _, segment := range segments {
		if segmentContainsStructuredContextNeedle(segment, prefix, lowerNeedle) {
			return true, true
		}
	}
	return false, true
}

func asciiHasFoldedPrefix(s, lowerPrefix string) bool {
	if len(s) < len(lowerPrefix) {
		return false
	}
	for i := 0; i < len(lowerPrefix); i++ {
		ch := s[i]
		if ch >= 0x80 || lowerPrefix[i] >= 0x80 {
			return strings.HasPrefix(lowerString(s), lowerPrefix)
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch != lowerPrefix[i] {
			return false
		}
	}
	return true
}

func rawSegmentsContainFolded(segments []string, needle string) bool {
	for _, segment := range segments {
		if valContainsFoldedNeedle(segment, needle) {
			return true
		}
	}
	return false
}
