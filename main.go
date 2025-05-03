package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
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
	Log           LogConf
	Keycloak      KeycloakConf
	Discord       DiscordConf
	StateFilePath string `envconfig:"STATE_FILE_PATH,default=./discroak_state.json"`
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
	// AlternativeRoleID is the role ID to be assigned when a role is removed
	AlternativeRoleID string `envconfig:"optional,ALTERNATIVE_ROLE_ID"`
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
		zap.String("stateFilePath", Config.StateFilePath),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Keycloakからユーザー情報を取得
	keycloakUsers, err := fetchKeycloakUsers(ctx, logger, Config.Keycloak)
	if err != nil {
		logger.Fatal("fetch users in keycloak failed", zap.Error(err))
	}

	// KeycloakユーザーからDiscord IDを抽出（この時点ではDiscordに接続しない）
	keycloakDiscordIDs := extractDiscordIDsFromKeycloak(logger, keycloakUsers, Config.Keycloak.AttrsKey)
	logger.Debug("discord IDs extracted from keycloak", zap.Any("ids", keycloakDiscordIDs))

	// 前回の状態を読み込む
	prevState, err := LoadState(Config.StateFilePath)
	if err != nil {
		logger.Warn("failed to load previous state", zap.Error(err), zap.String("path", Config.StateFilePath))
		// エラーが発生しても処理は続行
		prevState = &StateData{
			UsersInKeycloak: []string{},
			BuinUsers:       []string{},
		}
	}

	// 差分があるか確認（Discord接続前）
	hasDiff := hasDiffInSlices(prevState.UsersInKeycloak, keycloakDiscordIDs)

	// 現在のKeycloak情報を保存
	currentState := &StateData{
		UsersInKeycloak: keycloakDiscordIDs,
		BuinUsers:       prevState.BuinUsers, // この時点ではDiscordに接続していないので前回の情報を使用
	}

	// 差分がない場合は処理をスキップ
	if !hasDiff {
		logger.Info("no difference detected in keycloak users, skipping discord operations")
		return
	}

	logger.Info("difference detected in keycloak users, connecting to discord")

	// 差分がある場合のみDiscordに接続
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

	// Discordからユーザー情報を取得
	members, err := sess.GuildMembers(guild.ID, "", 1000)
	if err != nil {
		logger.Error("fetch guild members error", zap.Error(err))
	}

	// KeycloakのDiscord IDに対応するDiscordユーザーを取得
	keycloakCircleMembers := getKeycloakCircleMembers(logger, keycloakUsers, members, Config.Keycloak.AttrsKey)
	usersInKeycloak := lo.FlatMap(keycloakCircleMembers, func(user keycloakUser, _ int) []*discordgo.User { return user.DiscordUsers })
	logger.Debug("users in keycloak with attribute", zap.Any("users", usersInKeycloak))

	// 特定のロールを持つDiscordユーザーを取得
	buinUsers := lo.FilterMap(members, func(member *discordgo.Member, _ int) (*discordgo.User, bool) {
		return member.User, lo.ContainsBy(member.Roles, func(role string) bool {
			return role == Config.Discord.RoleID
		})
	})
	logger.Debug("users with specific roles in discord", zap.Any("users", buinUsers))

	// 現在の状態を更新して保存
	currentState.BuinUsers = lo.Map(buinUsers, func(user *discordgo.User, _ int) string {
		return user.ID
	})
	if err := SaveState(Config.StateFilePath, usersInKeycloak, buinUsers); err != nil {
		logger.Warn("failed to save current state", zap.Error(err), zap.String("path", Config.StateFilePath))
	} else {
		logger.Info("saved current state to file", zap.String("path", Config.StateFilePath))
	}

	logger.Info("proceeding with role operations")

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

	// 代替ロールが付与されたユーザーを追跡するためのリスト
	var alternativeRoleTargets []*discordgo.User

	// ロール剥奪処理は DisableRoleRemoval が false の場合のみ実行
	if !Config.Discord.DisableRoleRemoval {
		removeCh := make(chan *discordgo.User)
		resultCh := make(chan *discordgo.User, len(removeRoleTargets))
		var removeWg sync.WaitGroup
		for i := 0; i < maxWorkers; i++ {
			removeWg.Add(1)
			go func() {
				defer removeWg.Done()
				for item := range removeCh {
					if err := sess.GuildMemberRoleRemove(Config.Discord.GuildID, item.ID, Config.Discord.RoleID); err != nil {
						logger.Error("role delete failed", zap.Error(err), zap.String("username", item.Username))
					} else {
						// 代替ロールが設定されている場合は、そのロールを付与する
						if Config.Discord.AlternativeRoleID != "" {
							if err := sess.GuildMemberRoleAdd(Config.Discord.GuildID, item.ID, Config.Discord.AlternativeRoleID); err != nil {
								logger.Error("alternative role add failed", zap.Error(err), zap.String("username", item.Username))
							} else {
								logger.Info("alternative role added", zap.String("username", item.Username), zap.String("roleID", Config.Discord.AlternativeRoleID))
								resultCh <- item
							}
						}
					}
				}
			}()
		}
		for _, item := range removeRoleTargets {
			removeCh <- item
		}
		close(removeCh)
		removeWg.Wait()

		// 代替ロールが付与されたユーザーを収集
		close(resultCh)
		for item := range resultCh {
			alternativeRoleTargets = append(alternativeRoleTargets, item)
		}
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
		var notifyAlternativeUsers []*discordgo.User
		if !Config.Discord.DisableRoleRemoval {
			notifyRemoveUsers = removeRoleTargets
			notifyAlternativeUsers = alternativeRoleTargets
		}
		if len(addRoleTargets) != 0 || len(notifyRemoveUsers) != 0 || len(notifyAlternativeUsers) != 0 {
			err := PostResult(sess, Config.Discord.NotifyChannelID, addRoleTargets, notifyRemoveUsers, notifyAlternativeUsers)
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
{{- if .AlternativeNames }}
代替ロールを付与したユーザー
{{ .Quote }}
{{ .AlternativeNames | join "\n" }}
{{ .Quote }}
{{- end }}
`))

func CreateMsg(addUsers, removeUsers, alternativeUsers []string) (string, error) {
	if len(addUsers) == 0 && len(removeUsers) == 0 && len(alternativeUsers) == 0 {
		return "", nil
	}
	buf := new(bytes.Buffer)
	msgStr := struct {
		Quote            string
		AddNames         []string
		RemoveNames      []string
		AlternativeNames []string
	}{
		Quote:            "```",
		AddNames:         addUsers,
		RemoveNames:      removeUsers,
		AlternativeNames: alternativeUsers,
	}
	if err := postMsgTmpl.Execute(buf, msgStr); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func PostResult(session *discordgo.Session, channelID string, addUsers, removeUsers, alternativeUsers []*discordgo.User) error {
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
	alternativeUsersScreen := lo.Map(alternativeUsers, func(user *discordgo.User, _ int) string {
		if user.Discriminator == "" || user.Discriminator == "0" {
			return user.Username
		}
		return fmt.Sprintf("%s#%s", user.Username, user.Discriminator)
	})
	content, err := CreateMsg(addUsersScreen, deleteUsersScreen, alternativeUsersScreen)
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

// extractDiscordIDsFromKeycloak はKeycloakユーザー情報からDiscord IDを抽出する
func extractDiscordIDsFromKeycloak(logger *zap.Logger, keycloakUsers []*gocloak.User, attrsKey string) []string {
	var discordIDs []string

	for _, user := range keycloakUsers {
		if user.Attributes == nil {
			logger.Info("user attributes not found", zap.Any("user", user))
			continue
		}

		attrs := *user.Attributes
		discordUsernames, ok := attrs[attrsKey]
		if !ok {
			logger.Info("attribute not found", zap.String("attr key", attrsKey), zap.Stringer("user", user))
			continue
		}

		for _, item := range discordUsernames {
			if !discordIDRe.MatchString(item) {
				logger.Warn("invalid discord ID format", zap.String("discord ID", item))
				continue
			}
			discordIDs = append(discordIDs, item)
		}
	}

	return discordIDs
}

// getKeycloakCircleMembers はKeycloakユーザー情報とDiscordメンバー情報から部員情報を取得する
func getKeycloakCircleMembers(logger *zap.Logger, keycloakUsers []*gocloak.User, discordMembers []*discordgo.Member, attrsKey string) []keycloakUser {
	return lo.FilterMap(keycloakUsers, func(user *gocloak.User, _ int) (keycloakUser, bool) {
		if user.Attributes == nil {
			logger.Info("user attributes not found", zap.Any("user", user))
			return keycloakUser{}, false
		}

		attrs := *user.Attributes
		discordUsernames, ok := attrs[attrsKey]
		if !ok {
			logger.Info("attribute not found", zap.String("attr key", attrsKey), zap.Stringer("user", user))
			return keycloakUser{}, false
		}

		discordUsers := lo.FilterMap(discordUsernames, func(item string, _ int) (*discordgo.User, bool) {
			if !discordIDRe.MatchString(item) {
				logger.Warn("invalid discord ID format", zap.String("discord ID", item))
				return nil, false
			}

			for _, member := range discordMembers {
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
}

// StateData は前回の処理結果を保存するための構造体
type StateData struct {
	UsersInKeycloak []string `json:"users_in_keycloak"`
	BuinUsers       []string `json:"buin_users"`
	// 代替ロールが付与されたユーザーのリスト
	AlternativeRoleUsers []string `json:"alternative_role_users"`
}

// SaveState は現在の状態をファイルに保存する
func SaveState(filePath string, usersInKeycloak, buinUsers []*discordgo.User) error {
	// ディレクトリが存在しない場合は作成
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// ユーザーIDのみを抽出
	keycloakUserIDs := lo.Map(usersInKeycloak, func(user *discordgo.User, _ int) string {
		return user.ID
	})
	buinUserIDs := lo.Map(buinUsers, func(user *discordgo.User, _ int) string {
		return user.ID
	})

	state := StateData{
		UsersInKeycloak: keycloakUserIDs,
		BuinUsers:       buinUserIDs,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state data: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// LoadState は前回の状態をファイルから読み込む
func LoadState(filePath string) (*StateData, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// ファイルが存在しない場合は空の状態を返す
			return &StateData{
				UsersInKeycloak: []string{},
				BuinUsers:       []string{},
			}, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state StateData
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state data: %w", err)
	}

	return &state, nil
}

// HasDiff は前回の状態と現在の状態に差分があるかどうかを確認する
func HasDiff(prevState *StateData, currentKeycloakUsers, currentBuinUsers []*discordgo.User) bool {
	// 現在のユーザーIDのみを抽出
	currentKeycloakIDs := lo.Map(currentKeycloakUsers, func(user *discordgo.User, _ int) string {
		return user.ID
	})
	currentBuinIDs := lo.Map(currentBuinUsers, func(user *discordgo.User, _ int) string {
		return user.ID
	})

	// Keycloakユーザーの差分を確認
	keycloakDiff := hasDiffInSlices(prevState.UsersInKeycloak, currentKeycloakIDs)

	// 部員ユーザーの差分を確認
	buinDiff := hasDiffInSlices(prevState.BuinUsers, currentBuinIDs)

	return keycloakDiff || buinDiff
}

// hasDiffInSlices は2つの文字列スライスに差分があるかどうかを確認する
func hasDiffInSlices(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return true
	}

	// slice1の要素がslice2に含まれているかを確認
	for _, item := range slice1 {
		if !lo.Contains(slice2, item) {
			return true
		}
	}

	// slice2の要素がslice1に含まれているかを確認
	for _, item := range slice2 {
		if !lo.Contains(slice1, item) {
			return true
		}
	}

	return false
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
