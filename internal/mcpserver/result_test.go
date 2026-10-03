package mcpserver

import (
	"strings"
	"testing"
)

func TestResultCapNamesHowToNarrow(t *testing.T) {
	large := map[string]any{"objects": strings.Repeat("x", 70<<10)}
	if _, _, err := result("list_policy_objects", large, 64<<10); err == nil || !strings.Contains(err.Error(), "max_result_bytes") || !strings.Contains(err.Error(), "offset") {
		t.Fatalf("error = %v, want the limit and paging advice", err)
	}
	response, _, err := result("list_policy_objects", map[string]any{"objects": []any{}}, 64<<10)
	if err != nil || response == nil || len(response.Content) != 1 {
		t.Fatalf("small result = %#v, %v", response, err)
	}
	if _, _, err := result("inventory_status", large, 0); err != nil {
		t.Fatalf("no cap configured: %v", err)
	}
}
