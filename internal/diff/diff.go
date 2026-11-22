package diff

import (
	"fmt"
	"strings"
)

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type editOp struct {
	kind opKind
	line string
	oldN int
	newN int
}

// Unified produces a readable unified diff between oldText and newText.
func Unified(path, oldText, newText string) string {
	if oldText == newText {
		return ""
	}
	a := splitLines(oldText)
	b := splitLines(newText)

	var ops []editOp
	// Trim common prefix and suffix to keep DP small even on large files.
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}

	for i := 0; i < prefix; i++ {
		ops = append(ops, editOp{kind: opEqual, line: a[i], oldN: i + 1, newN: i + 1})
	}

	midA := a[prefix : len(a)-suffix]
	midB := b[prefix : len(b)-suffix]

	if len(midA)*len(midB) <= 4_000_000 {
		ops = append(ops, lcsDiff(midA, midB, prefix, prefix)...)
	} else {
		// Fallback for enormous changed regions.
		for i, l := range midA {
			ops = append(ops, editOp{kind: opDelete, line: l, oldN: prefix + i + 1})
		}
		for j, l := range midB {
			ops = append(ops, editOp{kind: opInsert, line: l, newN: prefix + j + 1})
		}
	}

	oldTailStart := len(a) - suffix
	newTailStart := len(b) - suffix
	for i := 0; i < suffix; i++ {
		ops = append(ops, editOp{
			kind: opEqual,
			line: a[oldTailStart+i],
			oldN: oldTailStart + i + 1,
			newN: newTailStart + i + 1,
		})
	}

	return formatHunks(path, ops, 3)
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func lcsDiff(a, b []string, oldOff, newOff int) []editOp {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var ops []editOp
	i, j := 0, 0
	for i < m && j < n {
		if a[i] == b[j] {
			ops = append(ops, editOp{kind: opEqual, line: a[i], oldN: oldOff + i + 1, newN: newOff + j + 1})
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			ops = append(ops, editOp{kind: opDelete, line: a[i], oldN: oldOff + i + 1})
			i++
		} else {
			ops = append(ops, editOp{kind: opInsert, line: b[j], newN: newOff + j + 1})
			j++
		}
	}
	for i < m {
		ops = append(ops, editOp{kind: opDelete, line: a[i], oldN: oldOff + i + 1})
		i++
	}
	for j < n {
		ops = append(ops, editOp{kind: opInsert, line: b[j], newN: newOff + j + 1})
		j++
	}
	return ops
}

func formatHunks(path string, ops []editOp, ctx int) string {
	var changed []int
	for idx, op := range ops {
		if op.kind != opEqual {
			changed = append(changed, idx)
		}
	}
	if len(changed) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- a/%s\n+++ b/%s\n", path, path))

	type span struct{ start, end int }
	var spans []span
	for _, idx := range changed {
		s := idx - ctx
		if s < 0 {
			s = 0
		}
		e := idx + ctx + 1
		if e > len(ops) {
			e = len(ops)
		}
		if len(spans) > 0 && s <= spans[len(spans)-1].end {
			if e > spans[len(spans)-1].end {
				spans[len(spans)-1].end = e
			}
		} else {
			spans = append(spans, span{s, e})
		}
	}

	for _, sp := range spans {
		oldStart, newStart := 0, 0
		oldCount, newCount := 0, 0
		for _, op := range ops[sp.start:sp.end] {
			switch op.kind {
			case opEqual:
				if oldStart == 0 {
					oldStart = op.oldN
				}
				if newStart == 0 {
					newStart = op.newN
				}
				oldCount++
				newCount++
			case opDelete:
				if oldStart == 0 {
					oldStart = op.oldN
				}
				oldCount++
			case opInsert:
				if newStart == 0 {
					newStart = op.newN
				}
				newCount++
			}
		}
		sb.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount))
		for _, op := range ops[sp.start:sp.end] {
			switch op.kind {
			case opEqual:
				sb.WriteString(" " + op.line + "\n")
			case opDelete:
				sb.WriteString("-" + op.line + "\n")
			case opInsert:
				sb.WriteString("+" + op.line + "\n")
			}
		}
	}
	return sb.String()
}

// Colorize renders a unified diff with ANSI colors for terminal display.
func Colorize(u string) string {
	const (
		reset = "\033[0m"
		red   = "\033[31m"
		green = "\033[32m"
		cyan  = "\033[36m"
		bold  = "\033[1m"
	)
	var sb strings.Builder
	lines := strings.Split(strings.TrimSuffix(u, "\n"), "\n")
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "+++") || strings.HasPrefix(l, "---"):
			sb.WriteString(bold + l + reset + "\n")
		case strings.HasPrefix(l, "@@"):
			sb.WriteString(cyan + l + reset + "\n")
		case strings.HasPrefix(l, "+"):
			sb.WriteString(green + l + reset + "\n")
		case strings.HasPrefix(l, "-"):
			sb.WriteString(red + l + reset + "\n")
		default:
			sb.WriteString(l + "\n")
		}
	}
	return sb.String()
}
