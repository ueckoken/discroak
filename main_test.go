package main

import (
	"strings"
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
			input1: []string{"a", "b", "c"},
			input2: []string{"z", "y", "x"},
			expect: strings.Join([]string{
				"ロールの操作をしました。",
				"ロールを付与したユーザー",
				"```",
				"a",
				"b",
				"c",
				"",
				"```",
				"ロールを剥奪したユーザー",
				"```",
				"z",
				"y",
				"x",
				"",
				"```",
				"",
			}, "\n"),
			wantErr: false,
		},
		"exist input1 and not exist input2": {
			input1: []string{"a", "b", "c"},
			input2: []string{},
			expect: strings.Join([]string{
				"ロールの操作をしました。",
				"ロールを付与したユーザー",
				"```",
				"a",
				"b",
				"c",
				"",
				"```",
				"ロールを剥奪したユーザー",
				"```",
				"いません",
				"```",
				"",
			}, "\n"),
			wantErr: false,
		},
		"not exist input1 and exist input2": {
			input1: []string{},
			input2: []string{"z", "y", "x"},
			expect: strings.Join([]string{
				"ロールの操作をしました。",
				"ロールを付与したユーザー",
				"```",
				"いません",
				"```",
				"ロールを剥奪したユーザー",
				"```",
				"z",
				"y",
				"x",
				"",
				"```",
				"",
			}, "\n"),
			wantErr: false,
		},
		"no exist input1 and input2": {
			input1: []string{},
			input2: []string{},
			expect: strings.Join([]string{
				"ロールの操作をしました。",
				"ロールを付与したユーザー",
				"```",
				"いません",
				"```",
				"ロールを剥奪したユーザー",
				"```",
				"いません",
				"```",
				"",
			}, "\n"),
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
