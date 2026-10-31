package pbx

import "testing"

// TestParseCallerID covers the shapes Asterisk actually emits for an
// endpoint's callerid, including the ones that mean "nothing set".
func TestParseCallerID(t *testing.T) {
	for _, tc := range []struct {
		in        string
		name, num string
	}{
		{`"Buero 1001" <1001>`, "Buero 1001", "1001"},
		{`Buero <1001>`, "Buero", "1001"},
		{`<1001>`, "", "1001"},
		{`"Buero 1001"`, "Buero 1001", ""},
		{`1001`, "1001", ""},
		{`"" <1001>`, "", "1001"},
		{`<unknown>`, "", ""},
		{`"<unknown>" <unknown>`, "", ""},
		{``, "", ""},
		{`   `, "", ""},
	} {
		name, num := parseCallerID(tc.in)
		if name != tc.name || num != tc.num {
			t.Errorf("parseCallerID(%q) = (%q, %q), want (%q, %q)", tc.in, name, num, tc.name, tc.num)
		}
	}
}
