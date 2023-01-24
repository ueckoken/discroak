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

func TestCreateMsg(t *testing.T) {
	testCases := map[string]struct {
		input1  []string
		input2  []string
		expect  string
		wantErr bool
	}{
		"exist input1 and input2": {
			input1:  []string{"a", "b", "c"},
			input2:  []string{"z", "y", "x"},
			expect:  "ロールの操作をしました。\nロールを付与したユーザー\n```\na\nb\nc\n```\nロールを剥奪したユーザー\n```\nz\ny\nx\n```\n",
			wantErr: false,
		},
		"no exist input1 and input2": {
			input1:  []string{},
			input2:  []string{},
			expect:  "ロールの操作をしました。\nロールを付与したユーザー\n```\n```\nロールを剥奪したユーザー\n```\n```\n",
			wantErr: false,
		},
	}
	for k, v := range testCases {
		t.Run(k, func(t *testing.T) {
			actual, err := CreateMsg(v.input1, v.input2)
			if v.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, v.expect, actual)
		})
	}

}
