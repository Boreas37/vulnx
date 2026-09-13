package renderer

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/vulnx/v2"
)

// RED test for issue #81: references should be renderable in list view via {references}
func TestReferencesPlaceholder(t *testing.T) {
	entry := &Entry{
		DocID:    "CVE-2024-1234",
		Severity: "critical",
		Name:     "Example",
		Citations: []*vulnx.Citation{
			{URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234", Source: "nvd"},
			{URL: "https://github.com/advisories/GHSA-test", Source: "github"},
			{URL: "https://example.com/third", Source: "other"},
		},
	}

	layout := []LayoutLine{
		{Line: 7, Format: "  ↳ References: {references}", OmitIf: []string{"citations.length == 0"}},
	}

	result := RenderWithColors([]*Entry{entry}, layout, 1, 1, NoColorConfig())

	if !strings.Contains(result, "https://nvd.nist.gov/vuln/detail/CVE-2024-1234") {
		t.Errorf("expected references to contain first citation URL, got:\n%s", result)
	}
	if !strings.Contains(result, "https://github.com/advisories/GHSA-test") {
		t.Errorf("expected references to contain second citation URL, got:\n%s", result)
	}
}

func TestReferencesPlaceholderEmptyOmitted(t *testing.T) {
	entry := &Entry{
		DocID:     "CVE-2024-9999",
		Severity:  "low",
		Name:      "No refs",
		Citations: nil,
	}

	layout := []LayoutLine{
		{Line: 7, Format: "  ↳ References: {references}", OmitIf: []string{"citations.length == 0"}},
	}

	result := RenderWithColors([]*Entry{entry}, layout, 1, 1, NoColorConfig())

	if strings.Contains(result, "References:") {
		t.Errorf("expected references line to be omitted when citations empty, got:\n%s", result)
	}
}
