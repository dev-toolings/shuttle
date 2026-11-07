package cli

import "testing"

// A helper that predates the reclaim refuses it at one of two depths, and the
// fleet runs both: in the dispatch ("unsupported signed root operation") or
// earlier, in rootplan.Verify ("unsupported root-operation contract"). The one
// message that names the fix must be reachable from either, and never from an
// unrelated failure.
func TestAnOlderRootHelperIsRecognisedAtBothRefusalDepths(t *testing.T) {
	for stderr, want := range map[string]bool{
		"unsupported signed root operation":                          true,
		"unsupported root-operation contract":                        true,
		"host identity does not match signed root operation":         false,
		"another root operation is still active after waiting 10m0s": false,
		"": false,
	} {
		if got := rootHelperLacksOperation(stderr); got != want {
			t.Errorf("%q: lacks operation=%v, want %v", stderr, got, want)
		}
	}
}
