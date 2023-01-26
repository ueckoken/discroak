package main

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"text/template"

	"github.com/Nerzal/gocloak/v12"
	"github.com/azuki-bar/goset"
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
	Level         *MyLogLevel `envconfig:"default=info"`
	IsDevelopment bool        `envconfig:"default=false"`
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
	EndPoint   string
	UserName   string
	Password   string
	LoginRealm string
	UserRealm  string
	AttrsKey   string
	GroupPath  string
}

type DiscordConf struct {
	Token           string
	GuildID         string
	RoleID          string
	NotifyChannelID string   `envconfig:"optional"`
	IgnoreUserIDs   []string `envconfig:"optional"`
}

var Config Conf
var Version = "snapshot"

func main() {
	if err := envconfig.InitWithOptions(&Config, envconfig.Options{}); err != nil {
		panic(err)
	}
	logger := zap.Must(func() (*zap.Logger, error) {
		if Config.Log.IsDevelopment {
			return zap.NewDevelopment(zap.IncreaseLevel(zapcore.Level(*Config.Log.Level)))
		}
		return zap.NewProduction(zap.IncreaseLevel(zapcore.Level(*Config.Log.Level)))
	}())
	logger.Info("init logger successful", zap.Stringer("loglevel", logger.Level()), zap.String("version", Version))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keycloakUsers, err := fetchKeycloakUsers(ctx, logger, Config.Keycloak)
	if err != nil {
		logger.Fatal("fetch users in keycloak failed", zap.Error(err))
	}
	sess, err := discordgo.New("Bot " + Config.Discord.Token)
	if err != nil {
		logger.Fatal("discord login failed", zap.Error(err))
	}
	if err := sess.Open(); err != nil {
		logger.Fatal("open websocket connection failed", zap.Error(err))
	}
	defer sess.Close()
	guild, err := sess.Guild(Config.Discord.GuildID)
	if err != nil {
		logger.Fatal("discord guild fetch failed", zap.Error(err), zap.String("guildID", Config.Discord.GuildID))
	}
	keycloakCircleMembers := lo.FilterMap(keycloakUsers, func(user *gocloak.User, _ int) (keycloakUser, bool) {
		if user.Attributes == nil {
			logger.Info("user attributes not found", zap.Any("user", user))
			return keycloakUser{}, false
		}
		attrs := *user.Attributes
		discordUsernames, ok := attrs[Config.Keycloak.AttrsKey]
		if !ok {
			logger.Info("attribute not found", zap.String("attr key", Config.Keycloak.AttrsKey), zap.Stringer("user", user))
			return keycloakUser{}, false
		}
		discordUsers := lo.FilterMap(discordUsernames, func(item string, _ int) (*discordgo.User, bool) {
			user, err := ScreenName2user(logger, sess, guild.ID, item)
			if err != nil {
				logger.Warn("user not found", zap.Error(err), zap.String("discord username", item))
				return nil, false
			}
			return user, true
		})
		return keycloakUser{
			KeycloakUser: user,
			DiscordUsers: discordUsers,
		}, true
	})

	// aggredUsersのDiscordUsersに対してflatmapして集合を作る
	// 部員ロール集合も持ってくる
	// 1. flatten(DiscordUsers) - 部員 を作る
	// 2. 部員ロール - flatten(DiscordUsers)を作る
	// 1に含まれるユーザに対して部員ロールを付与
	// 2に含まれるユーザに対して部員ロールを剥奪
	usersInKeycloak := lo.FlatMap(keycloakCircleMembers, func(user keycloakUser, _ int) []*discordgo.User { return user.DiscordUsers })
	logger.Debug("users in keycloak with attribute", zap.Any("users", usersInKeycloak))
	members, err := sess.GuildMembers(guild.ID, "", 1000)
	if err != nil {
		logger.Error("fetch guild members error", zap.Error(err))
	}
	buinUsers := lo.FilterMap(members, func(member *discordgo.Member, _ int) (*discordgo.User, bool) {
		return member.User, lo.ContainsBy(member.Roles, func(role string) bool {
			return role == Config.Discord.RoleID
		})
	})
	logger.Debug("users with specific roles in discord", zap.Any("users", buinUsers))
	addRoleTargets := goset.Difference(usersInKeycloak, buinUsers, func(key *discordgo.User) string { return key.ID })
	logger.Info("add role users", zap.Stringers("users", addRoleTargets))
	removeRoleTargets := goset.Difference(buinUsers, usersInKeycloak, func(key *discordgo.User) string { return key.ID })
	logger.Info("role remove users", zap.Stringers("users", removeRoleTargets))

	// 無視するべきIDを除外して、ロール操作を実行
	lo.ForEach(
		lo.Filter(addRoleTargets, func(user *discordgo.User, index int) bool { return !lo.Contains(Config.Discord.IgnoreUserIDs, user.ID) }),
		func(item *discordgo.User, _ int) {
			if err := sess.GuildMemberRoleAdd(Config.Discord.GuildID, item.ID, Config.Discord.RoleID); err != nil {
				logger.Error("role add failed", zap.Error(err), zap.String("username", item.Username))
			}
		})

	lo.ForEach(
		lo.Filter(removeRoleTargets, func(user *discordgo.User, index int) bool { return !lo.Contains(Config.Discord.IgnoreUserIDs, user.ID) }),
		func(item *discordgo.User, _ int) {
			if err := sess.GuildMemberRoleRemove(Config.Discord.GuildID, item.ID, Config.Discord.RoleID); err != nil {
				logger.Error("role delete failed", zap.Error(err), zap.String("username", item.Username))
			}
		})

	logger.Info("task is over!",
		zap.Stringers("role add users", addRoleTargets),
		zap.Stringers("role remove users", removeRoleTargets),
	)
	if Config.Discord.NotifyChannelID != "" && (len(addRoleTargets) != 0 || len(removeRoleTargets) != 0) {
		err := PostResult(sess, Config.Discord.NotifyChannelID, addRoleTargets, removeRoleTargets)
		if err != nil {
			logger.Error("post role modify info failed", zap.Error(err))
		}
	}
}

var postMsgTmpl = template.Must(template.New("sendResult").Parse(`ロールの操作をしました。
ロールを付与したユーザー
{{ .Quote }}
{{ range .AddNames }}{{- . }}{{ "\n" }}{{ else }}いません{{ "\n" }}{{- end }}{{ .Quote }}
ロールを剥奪したユーザー
{{ .Quote }}
{{ range .RemoveNames }}{{- . }}{{ "\n" }}{{ else }}いません{{ "\n" }}{{- end }}{{ .Quote }}
`))

func CreateMsg(addUsers, removeUsers []string) (string, error) {
	buf := new(bytes.Buffer)
	msgStr := struct {
		Quote       string
		AddNames    []string
		RemoveNames []string
	}{
		Quote:       "```",
		AddNames:    addUsers,
		RemoveNames: removeUsers,
	}
	if err := postMsgTmpl.Execute(buf, msgStr); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func PostResult(session *discordgo.Session, channelID string, addUsers, removeUsers []*discordgo.User) error {
	addUsersScreen := lo.Map(addUsers, func(user *discordgo.User, _ int) string {
		return fmt.Sprintf("%s#%s", user.Username, user.Discriminator)
	})
	deleteUsersScreen := lo.Map(removeUsers, func(user *discordgo.User, _ int) string {
		return fmt.Sprintf("%s#%s", user.Username, user.Discriminator)
	})
	content, err := CreateMsg(addUsersScreen, deleteUsersScreen)
	if err != nil {
		return err
	}
	_, err = session.ChannelMessageSend(channelID, content)
	return err
}

type keycloakUser struct {
	KeycloakUser *gocloak.User
	DiscordUsers []*discordgo.User
}

func fetchKeycloakUsers(ctx context.Context, logger *zap.Logger, conf KeycloakConf) ([]*gocloak.User, error) {
	cloakClient := gocloak.NewClient(conf.EndPoint)
	token, err := cloakClient.LoginAdmin(ctx, conf.UserName, conf.Password, conf.LoginRealm)
	if err != nil {
		return nil, fmt.Errorf("login to keycloak failed, err=`%w`", err)
	}
	group, err := cloakClient.GetGroupByPath(ctx, token.AccessToken, conf.UserRealm, conf.GroupPath)
	if err != nil {
		logger.Fatal("get group by path failed", zap.Error(err), zap.String("grouppath", conf.GroupPath))
		return nil, fmt.Errorf("get group by path failed,err=`%w`", err)
	}
	logger.Debug("user in keycloak joined in group", zap.Any("group", group))
	keycloakUsers, err := cloakClient.GetGroupMembers(ctx, token.AccessToken, conf.UserRealm, *group.ID, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, fmt.Errorf("get users failed, err=`%w`", err)
	}
	return keycloakUsers, nil
}

func ScreenName2user(logger *zap.Logger, sess *discordgo.Session, guildID string, screenName string) (*discordgo.User, error) {
	members, err := sess.GuildMembers(Config.Discord.GuildID, "", 1000)
	if err != nil {
		return nil, fmt.Errorf("guildmember fetch failed,err=`%w`", err)
	}
	name, discriminator, err := DiscordUserParse(screenName)
	if err != nil {
		return nil, fmt.Errorf("parse failed,err=`%w`", err)
	}
	users := lo.FilterMap(members, func(item *discordgo.Member, _ int) (*discordgo.User, bool) {
		if item.User.Username == name && item.User.Discriminator == discriminator {
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

var usernameRe = regexp.MustCompile(`(^.{2,32})#(\d{4}$)`)

func DiscordUserParse(usernameRaw string) (username, discriminator string, err error) {
	parsed := usernameRe.FindStringSubmatch(usernameRaw)
	switch len(parsed) {
	case 0, 1, 2:
		return "", "", fmt.Errorf("parsed failed, no group match")
	case 3:
		return parsed[1], parsed[2], nil
	default:
		return "", "", fmt.Errorf("parse failed")
	}
}
