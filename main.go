package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"regexp"
	"sync"

	"github.com/Masterminds/sprig/v3"
	"github.com/Nerzal/gocloak/v12"
	"github.com/azuki-bar/goset"
	"github.com/bwmarrin/discordgo"
	"github.com/samber/lo"
	"github.com/vrischmann/envconfig"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/exp/utf8string"
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
	NotifyChannelID string `envconfig:"optional"`
	// separated by `,`
	IgnoreUserIDs []string `envconfig:"optional,DISCORD_IGNORE_USER_IDS"`
	// DisableRoleRemoval disables the role removal feature when set to true
	DisableRoleRemoval bool `envconfig:"optional,DISABLE_ROLE_REMOVAL,default=false"`
}

// filled by goreleaser
var (
	version = "snapshot"
	commit  = "snapshot"
	date    = ""
)

func parseConfig() (*Conf, error) {
	var Config Conf
	err := envconfig.Init(&Config)
	return &Config, err
}
func main() {
	Config, err := parseConfig()
	if err != nil {
		panic(err)
	}
	logger := zap.Must(func() (*zap.Logger, error) {
		if Config.Log.IsDevelopment {
			return zap.NewDevelopment(zap.IncreaseLevel(zapcore.Level(*Config.Log.Level)))
		}
		return zap.NewProduction(zap.IncreaseLevel(zapcore.Level(*Config.Log.Level)))
	}())
	logger.Info("init logger successful",
		zap.Stringer("loglevel", logger.Level()),
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("buildDate", date),
		zap.String("discord.guildID", Config.Discord.GuildID),
		zap.String("discord.roleID", Config.Discord.RoleID),
		zap.String("discord.notifyChannelID", Config.Discord.NotifyChannelID),
		zap.Bool("discord.disableRoleRemoval", Config.Discord.DisableRoleRemoval),
		zap.Strings("discord.ignoreUserIDs", Config.Discord.IgnoreUserIDs),
	)

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
			if !discordIDRe.MatchString(item) {
				logger.Warn("invalid discord ID format", zap.String("discord ID", item))
				return nil, false
			}
			members, err := sess.GuildMembers(guild.ID, "", 1000)
			if err != nil {
				logger.Warn("guildmember fetch failed", zap.Error(err), zap.String("discord ID", item))
				return nil, false
			}
			for _, member := range members {
				if member.User.ID == item {
					return member.User, true
				}
			}
			logger.Warn("user not found", zap.String("discord ID", item))
			return nil, false
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
	addRoleTargets := lo.Filter(
		goset.Difference(usersInKeycloak, buinUsers, func(key *discordgo.User) string { return key.ID }),
		// 無視するべきIDを除外する
		func(user *discordgo.User, _ int) bool { return !lo.Contains(Config.Discord.IgnoreUserIDs, user.ID) },
	)
	removeRoleTargets := lo.Filter(
		goset.Difference(buinUsers, usersInKeycloak, func(key *discordgo.User) string { return key.ID }),
		func(user *discordgo.User, _ int) bool { return !lo.Contains(Config.Discord.IgnoreUserIDs, user.ID) },
	)
	// 並列数を制限するためのworker pool
	const maxWorkers = 5
	addCh := make(chan *discordgo.User)
	var addWg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		addWg.Add(1)
		go func() {
			defer addWg.Done()
			for item := range addCh {
				if err := sess.GuildMemberRoleAdd(Config.Discord.GuildID, item.ID, Config.Discord.RoleID); err != nil {
					logger.Error("role add failed", zap.Error(err), zap.String("username", item.Username))
				}
			}
		}()
	}
	for _, item := range addRoleTargets {
		addCh <- item
	}
	close(addCh)
	addWg.Wait()

	// ロール剥奪処理は DisableRoleRemoval が false の場合のみ実行
	if !Config.Discord.DisableRoleRemoval {
		removeCh := make(chan *discordgo.User)
		var removeWg sync.WaitGroup
		for i := 0; i < maxWorkers; i++ {
			removeWg.Add(1)
			go func() {
				defer removeWg.Done()
				for item := range removeCh {
					if err := sess.GuildMemberRoleRemove(Config.Discord.GuildID, item.ID, Config.Discord.RoleID); err != nil {
						logger.Error("role delete failed", zap.Error(err), zap.String("username", item.Username))
					}
				}
			}()
		}
		for _, item := range removeRoleTargets {
			removeCh <- item
		}
		close(removeCh)
		removeWg.Wait()
	} else {
		logger.Info("role removal is disabled by configuration")
	}

	if !Config.Discord.DisableRoleRemoval {
		logger.Info("task is over!",
			zap.Stringers("role add users", addRoleTargets),
			zap.Stringers("role remove users", removeRoleTargets),
		)
	} else {
		logger.Info("task is over! (role removal disabled)",
			zap.Stringers("role add users", addRoleTargets),
			zap.Stringers("role remove candidates (not removed)", removeRoleTargets),
		)
	}
	if Config.Discord.NotifyChannelID != "" {
		var notifyRemoveUsers []*discordgo.User
		if !Config.Discord.DisableRoleRemoval {
			notifyRemoveUsers = removeRoleTargets
		}
		if len(addRoleTargets) != 0 || len(notifyRemoveUsers) != 0 {
			err := PostResult(sess, Config.Discord.NotifyChannelID, addRoleTargets, notifyRemoveUsers)
			if err != nil {
				logger.Error("post role modify info failed", zap.Error(err))
			}
		}
	}
}

var postMsgTmpl = template.Must(
	template.
		New("sendResult").
		Funcs(sprig.FuncMap()).
		Parse(`ロールの操作をしました。
{{- if .AddNames }}
ロールを付与したユーザー
{{ .Quote }}
{{ .AddNames | join "\n" }}
{{ .Quote }}
{{- end }}
{{- if .RemoveNames }}
ロールを剥奪したユーザー
{{ .Quote }}
{{ .RemoveNames | join "\n" }}
{{ .Quote }}
{{- end }}
`))

func CreateMsg(addUsers, removeUsers []string) (string, error) {
	if len(addUsers) == 0 && len(removeUsers) == 0 {
		return "", nil
	}
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
		if user.Discriminator == "" || user.Discriminator == "0" {
			return user.Username
		}
		return fmt.Sprintf("%s#%s", user.Username, user.Discriminator)
	})
	deleteUsersScreen := lo.Map(removeUsers, func(user *discordgo.User, _ int) string {
		if user.Discriminator == "" || user.Discriminator == "0" {
			return user.Username
		}
		return fmt.Sprintf("%s#%s", user.Username, user.Discriminator)
	})
	content, err := CreateMsg(addUsersScreen, deleteUsersScreen)
	if err != nil {
		return err
	}
	// safeSlice similar to s.Slice(0,len) but safe for out of index.
	safeSlice := func(s *utf8string.String, len int) string {
		if s.RuneCount() > len {
			return s.Slice(0, len)
		}
		return s.Slice(0, s.RuneCount())
	}
	// 2000 is limit of discord post
	_, err = session.ChannelMessageSend(channelID, safeSlice(utf8string.NewString(content), 2000))
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

	// 最大 1000 件ずつ取って、足りなくなるまでループ
	const pageSize = 1000
	var allMembers []*gocloak.User
	for first := 0; ; first += pageSize {
		params := gocloak.GetGroupsParams{
			First: gocloak.IntP(first),
			Max:   gocloak.IntP(pageSize),
		}
		users, err := cloakClient.GetGroupMembers(ctx, token.AccessToken,
			conf.UserRealm, *group.ID, params)
		if err != nil {
			return nil, fmt.Errorf("get users failed, err=`%w`", err)
		}
		if len(users) == 0 {
			break // 取り切った
		}
		allMembers = append(allMembers, users...)
		logger.Debug("fetched keycloak users page",
			zap.Int("page", first/pageSize),
			zap.Int("count", len(users)),
			zap.Int("total_so_far", len(allMembers)))
	}

	return allMembers, nil
}

var discordIDRe = regexp.MustCompile(`^\d+$`)

func DiscordUserParse(usernameRaw string) (username, discriminator string, err error) {
	// Discord IDのみを受け付ける (数字であればOK)
	if discordIDRe.MatchString(usernameRaw) {
		return usernameRaw, "", nil
	}

	// Discord IDでない場合はエラーを返す
	return "", "", fmt.Errorf("input is not a valid Discord ID (must be numeric)")
}
