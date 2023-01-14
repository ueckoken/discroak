package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Nerzal/gocloak/v12"
	"github.com/bwmarrin/discordgo"
	"github.com/samber/lo"
	"github.com/vrischmann/envconfig"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Conf struct {
	Log      LogConf
	Keycloak KeycloakConf
	Discord  DiscordConf
}
type LogConf struct {
	Level         *MyLogLevel
	IsDevelopment bool
}
type MyLogLevel zapcore.Level

func (l *MyLogLevel) Unmarshal(s string) error {
	zapLevel := zapcore.Level(*l)
	if err := zapLevel.UnmarshalText([]byte(s)); err != nil {
		return err
	}
	*l = MyLogLevel(zapLevel)
	return nil
}

type KeycloakConf struct {
	EndPoint            string
	UserName            string
	Password            string
	Realm               string
	AcceptRealmRoleName string
	AttrsKey            string
}

type DiscordConf struct {
	Token   string
	GuildID string
	RoleID  string
}

var Config Conf

func init() {
	if err := envconfig.InitWithOptions(&Config, envconfig.Options{}); err != nil {
		panic(err)
	}
}
func main() {
	logger := zap.Must(func() (*zap.Logger, error) {
		if Config.Log.IsDevelopment {
			return zap.NewDevelopment(zap.IncreaseLevel(zapcore.Level(*Config.Log.Level)))
		}
		return zap.NewProduction(zap.IncreaseLevel(zapcore.Level(*Config.Log.Level)))
	}())
	cloakClient := gocloak.NewClient(Config.Keycloak.EndPoint)
	ctx := context.Background()
	token, err := cloakClient.LoginAdmin(ctx, Config.Keycloak.UserName, Config.Keycloak.Password, Config.Keycloak.Realm)
	if err != nil {
		logger.Fatal("login to keycloak failed", zap.Error(err))
	}
	keycloakUsers, err := cloakClient.GetUsers(ctx, token.AccessToken, Config.Keycloak.Realm, gocloak.GetUsersParams{})
	if err != nil {
		logger.Fatal("get users failed", zap.Error(err))
	}
	sess, err := discordgo.New("Bot " + Config.Discord.Token)
	if err != nil {
		panic(err)
	}
	guild, err := sess.Guild(Config.Discord.GuildID)
	if err != nil {
		panic(err)
	}
	keycloakCircleMembers := lo.FilterMap(keycloakUsers, func(user *gocloak.User, _ int) (keycloakUser, bool) {
		attrs := *user.Attributes
		discordUsernames, ok := attrs[Config.Keycloak.AttrsKey]
		if !ok {
			logger.Info("attribute not found", zap.String("attr key", Config.Keycloak.AttrsKey), zap.Stringer("user", user))
			return keycloakUser{}, false
		}
		if !lo.Contains(*user.RealmRoles, Config.Keycloak.AcceptRealmRoleName) {
			return keycloakUser{}, false
		}
		discordUsers := lo.FilterMap(discordUsernames, func(item string, _ int) (*discordgo.User, bool) {
			user, err := ScreenName2user(logger, sess, guild.ID, item)
			if err != nil {
				logger.Warn("user not found", zap.String("username", item))
				return nil, false
			}
			return user, true
		})
		return keycloakUser{
			KeycloakUser: user,
			DiscordUsers: discordUsers,
		}, true
	})

	// TODO: aggredUsersのDiscordUsersに対してflatmapして集合を作る
	// 部員ロール集合も持ってくる
	// 1. flatten(DiscordUsers) - 部員 を作る
	// 2. 部員ロール - flatten(DiscordUsers)を作る
	// 1に含まれるユーザに対して部員ロールを付与
	// 2に含まれるユーザに対して部員ロールを剥奪
	logger.Debug("fetch users", zap.Any("user", keycloakCircleMembers))
	usersInKeycloak := lo.FlatMap(keycloakCircleMembers, func(user keycloakUser, _ int) []*discordgo.User { return user.DiscordUsers })
	buinUsers := lo.FilterMap(guild.Members, func(item *discordgo.Member, _ int) (*discordgo.User, bool) {
		return item.User, lo.ContainsBy(item.Roles, func(item string) bool { return item == Config.Discord.RoleID })
	})
	addRoleUsers := difference(usersInKeycloak, buinUsers)
	depriveRoleUsers := difference(buinUsers, usersInKeycloak)

	lo.ForEach(addRoleUsers, func(item *discordgo.User, _ int) {
		if err := sess.GuildMemberRoleAdd(Config.Discord.GuildID, item.ID, Config.Discord.RoleID); err != nil {
			logger.Error("role add failed", zap.String("username", item.Username))
		}
	})
	lo.ForEach(depriveRoleUsers, func(item *discordgo.User, _ int) {
		if err := sess.GuildMemberRoleAdd(Config.Discord.GuildID, item.ID, Config.Discord.RoleID); err != nil {
			logger.Error("role delete failed", zap.String("username", item.Username))
		}
	})

}

type keycloakUser struct {
	KeycloakUser *gocloak.User
	DiscordUsers []*discordgo.User
}

func ScreenName2user(logger *zap.Logger, sess *discordgo.Session, guildID string, screenName string) (*discordgo.User, error) {
	guild, err := sess.Guild(guildID)
	if err != nil {
		return nil, err
	}
	users := lo.FilterMap(guild.Members, func(item *discordgo.Member, _ int) (*discordgo.User, bool) {
		if item.User.Username == screenName {
			return item.User, true
		}
		return nil, false
	})
	switch len(users) {
	case 0:
		return nil, fmt.Errorf("user not found")
	case 1:
		return users[0], nil
	default:
		logger.Info("match multipue users", zap.Stringers("users", users))
		return users[0], nil
	}
}

// difference returns the set difference calc by a - b.
func difference(a, b []*discordgo.User) []*discordgo.User {
	aMap := make(map[string]*discordgo.User)
	bMap := make(map[string]*discordgo.User)
	for _, user := range a {
		if _, ok := aMap[user.ID]; !ok {
			aMap[user.ID] = user
		}
	}
	for _, user := range b {
		if _, ok := bMap[user.ID]; !ok {
			bMap[user.ID] = user
		}
	}
	log.Println(aMap, bMap)
	diff := make([]*discordgo.User, 0)
	for ka, va := range aMap {
		if _, ok := bMap[ka]; !ok {
			diff = append(diff, va)
		}
	}
	return diff
}
