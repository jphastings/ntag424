package sdm_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/jphastings/ntag424/sdm"
	"github.com/stretchr/testify/assert"
)

func ExampleParseMirrorString() {
	ms, err := sdm.ParseMirrorString(`https://example.com/page?uid={{ .UID }}&ctr={{ .Counter }}&picc={{ .PICC }}`)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ms)
	// Output: https://example.com/page?uid=[ uid ]&ctr=[c]&picc=0[ uid ][c]
}

func TestParseMirrorString(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		output    string
		positions map[string]int
	}{
		{
			"All dynamic elements",
			`https://example.com/page?uid={{.UID}}&ctr={{ .Counter }}&picc={{ .PICC }}`,
			"https://example.com/page?uid=[ uid ]&ctr=[c]&picc=0[ uid ][c]",
			map[string]int{"UID": 29, "Counter": 41, "PICC": 50},
		}, {
			"UID only",
			`https://example.com/page?id={{ .UID }}`,
			`https://example.com/page?id=[ uid ]`,
			map[string]int{"UID": 28},
		}, {
			"Counter only",
			`https://example.com/page?ctr={{ .Counter }}`,
			`https://example.com/page?ctr=[c]`,
			map[string]int{"Counter": 29},
		}, {
			"PICC only",
			`https://example.com/page?picc={{ .PICC }}`,
			"https://example.com/page?picc=0[ uid ][c]",
			map[string]int{"PICC": 30},
		}, {
			"Ensuring whitespace parsing",
			`https://example.com/page?uid={{    .UID  }}&ctr={{.Counter}}&picc={{ .PICC }}`,
			"https://example.com/page?uid=[ uid ]&ctr=[c]&picc=0[ uid ][c]",
			map[string]int{"UID": 29, "Counter": 41, "PICC": 50},
		},
	}

	for _, c := range cases {
		ms, err := sdm.ParseMirrorString(c.input)
		assert.NoError(t, err)

		assert.Equal(t, c.output, ms.String())
		assert.Equal(t, c.positions, ms.Positions)
	}

}
