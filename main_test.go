package main

import (
	"testing"

	"github.com/bwmarrin/discordgo"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

func TestDifference(t *testing.T) {
	testPatterns := map[string]struct {
		a      []*discordgo.User
		b      []*discordgo.User
		expect []*discordgo.User
	}{
		"intersect": {
			a: []*discordgo.User{
				{ID: "1"},
				{ID: "2"},
			},
			b: []*discordgo.User{
				{ID: "3"},
				{ID: "2"},
				{ID: "3"},
			},
			expect: []*discordgo.User{
				{ID: "1"},
			},
		},
		"no a": {
			a: nil,
			b: []*discordgo.User{
				{ID: "3"},
				{ID: "2"},
				{ID: "3"},
			},
			expect: nil,
		},
		"no b": {
			a: []*discordgo.User{
				{ID: "1"},
				{ID: "2"},
			},
			b: nil,
			expect: []*discordgo.User{
				{ID: "1"},
				{ID: "2"},
			},
		},
	}

	extractIDs := func(users []*discordgo.User) []string {
		return lo.Map(users, func(item *discordgo.User, index int) string { return item.ID })
	}
	for k, v := range testPatterns {
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			actual := difference(v.a, v.b)
			assert.Equal(t, extractIDs(v.expect), extractIDs(actual))
		})
	}
}
