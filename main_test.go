package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	testPatterns := map[string]struct {
		envs    map[string]string
		expect  *Conf
		wantErr bool
	}{
		"no env": {
			envs:    make(map[string]string),
			wantErr: true,
			expect:  nil,
		},
		"insert array": {
			envs: map[string]string{
				"KEYCLOAK_ENDPOINT":       "1",
				"KEYCLOAK_USERNAME":       "1",
				"KEYCLOAK_PASSWORD":       "1",
				"KEYCLOAK_LOGIN_REALM":    "1",
				"KEYCLOAK_USER_REALM":     "1",
				"KEYCLOAK_ATTRS_KEY":      "1",
				"KEYCLOAK_GROUP_PATH":     "1",
				"DISCORD_TOKEN":           "1",
				"DISCORD_GUILD_ID":        "1",
				"DISCORD_ROLE_ID":         "1",
				"DISCORD_IGNORE_USER_IDS": "1234,5678",
			},
			expect: &Conf{
				Log: LogConf{
					Level:         new(MyLogLevel),
					IsDevelopment: false,
				},
				Keycloak: KeycloakConf{
					EndPoint:   "1",
					UserName:   "1",
					Password:   "1",
					LoginRealm: "1",
					UserRealm:  "1",
					AttrsKey:   "1",
					GroupPath:  "1",
				},
				Discord: DiscordConf{
					Token:           "1",
					GuildID:         "1",
					RoleID:          "1",
					NotifyChannelID: "",
					IgnoreUserIDs:   []string{"1234", "5678"},
				},
			},
		},
		"fill all": {
			envs: map[string]string{
				"KEYCLOAK_ENDPOINT":    "1",
				"KEYCLOAK_USERNAME":    "1",
				"KEYCLOAK_PASSWORD":    "1",
				"KEYCLOAK_LOGIN_REALM": "1",
				"KEYCLOAK_USER_REALM":  "1",
				"KEYCLOAK_ATTRS_KEY":   "1",
				"KEYCLOAK_GROUP_PATH":  "1",
				"DISCORD_TOKEN":        "1",
				"DISCORD_GUILD_ID":     "1",
				"DISCORD_ROLE_ID":      "1",
			},
			wantErr: false,
			expect: &Conf{
				Log: LogConf{
					Level:         new(MyLogLevel),
					IsDevelopment: false,
				},
				Keycloak: KeycloakConf{
					EndPoint:   "1",
					UserName:   "1",
					Password:   "1",
					LoginRealm: "1",
					UserRealm:  "1",
					AttrsKey:   "1",
					GroupPath:  "1",
				},
				Discord: DiscordConf{
					Token:           "1",
					GuildID:         "1",
					RoleID:          "1",
					NotifyChannelID: "",
					IgnoreUserIDs:   nil,
				},
			},
		},
	}
	for k, v := range testPatterns {
		t.Run(k, func(t *testing.T) {
			for key, val := range v.envs {
				t.Setenv(key, val)
			}
			actual, err := parseConfig()
			if v.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, v.expect, actual)
			}
		})
	}
}
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
	t.Run("new type username pattern", func(t *testing.T) {
		u, d, err := DiscordUserParse("username")
		assert.Empty(t, err)
		assert.Equal(t, "username", u)
		assert.Equal(t, "0", d)
	})
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
				"```",
				"ロールを剥奪したユーザー",
				"```",
				"z",
				"y",
				"x",
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
				"ロールを剥奪したユーザー",
				"```",
				"z",
				"y",
				"x",
				"```",
				"",
			}, "\n"),
			wantErr: false,
		},
		"no exist input1 and input2": {
			input1:  []string{},
			input2:  []string{},
			expect:  "",
			wantErr: false,
		},
	}
	for k, v := range testCases {
		t.Run(k, func(t *testing.T) {
			v := v
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
