package nakis

import (
	"fmt"
	"strconv"
	"strings"
)

func parseRanges(items []string) ([]Range, error) {
	out := make([]Range, 0, len(items))
	for _, it := range items {
		lo, hi, span := strings.Cut(it, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("shape_up: bad entry %q", it)
		}
		b := a
		if span {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("shape_up: bad entry %q", it)
			}
		}
		out = append(out, Range{a, b})
	}
	return out, nil
}
