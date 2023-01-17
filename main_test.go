package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscordUserParse(t *testing.T) {
	testPatterns := map[string]struct {
		input         string
		username      string
		descriminator string
		wantErr       bool
	}{
		"multibyte": {
			input:         "テスト#1234",
			username:      "テスト",
			descriminator: "1234",
			wantErr:       false,
		},
		"missmatch pattern": {
			input:   "onlyname",
			wantErr: true,
		},
		"misspattern": {
			input:   `a`,
			wantErr: true,
		},
	}
	for k, v := range testPatterns {
		t.Run(k, func(t *testing.T) {
			u, d, err := DiscordUserParse(v.input)
			if v.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, v.username, u)
			assert.Equal(t, v.descriminator, d)
		})
	}
}
