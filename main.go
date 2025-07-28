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
	"time"

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
	StateFilePath string        `envconfig:"STATE_FILE_PATH,default=./discroak_state.json"`
	RunOnce       bool          `envconfig:"RUN_ONCE,default=false"`
	CheckInterval time.Duration `envconfig:"CHECK_INTERVAL,default=5m"`
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
		zap.String("alternativeRoleID", Config.Discord.AlternativeRoleID),
		zap.Bool("runOnce", Config.RunOnce),
		zap.Duration("checkInterval", Config.CheckInterval),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1回だけ実行モード
	if Config.RunOnce {
		logger.Info("running in one-time mode")
		if err := runSyncTask(ctx, logger, Config); err != nil {
			logger.Fatal("sync task failed", zap.Error(err))
		}
		return
	}

	// 常時実行モード
	logger.Info("running in daemon mode", zap.Duration("interval", Config.CheckInterval))

	// Discord セッションを作成し、常時接続を維持
	sess, err := createDiscordSession(logger, Config.Discord.Token)
	if err != nil {
		logger.Fatal("discord session creation failed", zap.Error(err))
	}
	defer sess.Close()

	logger.Info("discord session established, starting periodic sync")

	// コマンドハンドラーを設定
	commandCh := make(chan commandRequest, 10)
	setupCommandHandlers(sess, commandCh, logger)

	// スラッシュコマンドを登録
	if err := registerSlashCommands(sess, Config.Discord.GuildID, logger); err != nil {
		logger.Error("failed to register slash commands", zap.Error(err))
	}

	currentInterval := Config.CheckInterval
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	// 初回実行
	if err := runSyncWithSession(ctx, logger, Config, sess); err != nil {
		logger.Error("initial sync failed", zap.Error(err))
	}

	// 定期実行
	for {
		select {
		case <-ctx.Done():
			logger.Info("context cancelled, shutting down")
			return
		case cmd := <-commandCh:
			if err := handleCommand(cmd, &currentInterval, ticker, logger); err != nil {
				logger.Error("command handling failed", zap.Error(err))
			}
		case <-ticker.C:
			logger.Debug("running periodic sync")
			if err := runSyncWithSession(ctx, logger, Config, sess); err != nil {
				logger.Error("periodic sync failed", zap.Error(err))

				// 接続エラーの場合は再接続を試行
				if isConnectionError(err) {
					logger.Warn("connection error detected, attempting to reconnect")
					sess.Close()
					newSess, reconnectErr := createDiscordSession(logger, Config.Discord.Token)
					if reconnectErr != nil {
						logger.Error("reconnection failed", zap.Error(reconnectErr))
						continue
					}
					sess = newSess
					logger.Info("successfully reconnected to discord")
				}
			}
		}
	}
}

func runSyncTask(ctx context.Context, logger *zap.Logger, config *Conf) error {
	sess, err := createDiscordSession(logger, config.Discord.Token)
	if err != nil {
		return fmt.Errorf("discord session creation failed: %w", err)
	}
	defer sess.Close()

	return runSyncWithSession(ctx, logger, config, sess)
}

func runSyncWithSession(ctx context.Context, logger *zap.Logger, config *Conf, sess *discordgo.Session) error {
	// Keycloakからユーザー情報を取得
	keycloakUsers, err := fetchKeycloakUsers(ctx, logger, config.Keycloak)
	if err != nil {
		return fmt.Errorf("fetch users in keycloak failed: %w", err)
	}

	// KeycloakユーザーからDiscord IDを抽出
	keycloakDiscordIDs := extractDiscordIDsFromKeycloak(logger, keycloakUsers, config.Keycloak.AttrsKey)
	logger.Debug("discord IDs extracted from keycloak", zap.Any("ids", keycloakDiscordIDs))

	// 前回の状態を読み込む
	prevState, err := LoadState(config.StateFilePath)
	if err != nil {
		logger.Warn("failed to load previous state", zap.Error(err), zap.String("path", config.StateFilePath))
		prevState = &StateData{
			UsersInKeycloak: []string{},
			BuinUsers:       []string{},
		}
	}

	// 差分があるか確認
	hasDiff := hasDiffInSlices(prevState.UsersInKeycloak, keycloakDiscordIDs)

	// 差分がない場合は処理をスキップ
	if !hasDiff {
		logger.Debug("no difference detected in keycloak users, skipping discord operations")
		return nil
	}

	logger.Info("difference detected in keycloak users, processing changes")

	guild, err := sess.Guild(config.Discord.GuildID)
	if err != nil {
		return fmt.Errorf("discord guild fetch failed: %w", err)
	}

	// Discordからユーザー情報を取得
	members, err := sess.GuildMembers(guild.ID, "", 1000)
	if err != nil {
		logger.Error("fetch guild members error", zap.Error(err))
	}

	// KeycloakのDiscord IDに対応するDiscordユーザーを取得
	keycloakCircleMembers := getKeycloakCircleMembers(logger, keycloakUsers, members, config.Keycloak.AttrsKey)
	usersInKeycloak := lo.FlatMap(keycloakCircleMembers, func(user keycloakUser, _ int) []*discordgo.User { return user.DiscordUsers })
	logger.Debug("users in keycloak with attribute", zap.Any("users", usersInKeycloak))

	// 特定のロールを持つDiscordユーザーを取得
	buinUsers := lo.FilterMap(members, func(member *discordgo.Member, _ int) (*discordgo.User, bool) {
		return member.User, lo.ContainsBy(member.Roles, func(role string) bool {
			return role == config.Discord.RoleID
		})
	})
	logger.Debug("users with specific roles in discord", zap.Any("users", buinUsers))

	// 現在の状態を更新して保存
	if err := SaveState(config.StateFilePath, usersInKeycloak, buinUsers); err != nil {
		logger.Warn("failed to save current state", zap.Error(err), zap.String("path", config.StateFilePath))
	} else {
		logger.Debug("saved current state to file", zap.String("path", config.StateFilePath))
	}

	logger.Info("proceeding with role operations")

	addRoleTargets := lo.Filter(
		goset.Difference(usersInKeycloak, buinUsers, func(key *discordgo.User) string { return key.ID }),
		func(user *discordgo.User, _ int) bool { return !lo.Contains(config.Discord.IgnoreUserIDs, user.ID) },
	)
	removeRoleTargets := lo.Filter(
		goset.Difference(buinUsers, usersInKeycloak, func(key *discordgo.User) string { return key.ID }),
		func(user *discordgo.User, _ int) bool { return !lo.Contains(config.Discord.IgnoreUserIDs, user.ID) },
	)

	// 並列数を制限するためのworker pool
	const maxWorkers = 2
	addCh := make(chan *discordgo.User)
	var addWg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		addWg.Add(1)
		go func() {
			defer addWg.Done()
			for item := range addCh {
				if err := executeWithRateLimit(func() error {
					return sess.GuildMemberRoleAdd(config.Discord.GuildID, item.ID, config.Discord.RoleID)
				}, logger); err != nil {
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
	if !config.Discord.DisableRoleRemoval {
		removeCh := make(chan *discordgo.User)
		resultCh := make(chan *discordgo.User, len(removeRoleTargets))
		var removeWg sync.WaitGroup
		for i := 0; i < maxWorkers; i++ {
			removeWg.Add(1)
			go func() {
				defer removeWg.Done()
				for item := range removeCh {
					if err := executeWithRateLimit(func() error {
						return sess.GuildMemberRoleRemove(config.Discord.GuildID, item.ID, config.Discord.RoleID)
					}, logger); err != nil {
						logger.Error("role delete failed", zap.Error(err), zap.String("username", item.Username))
					} else if config.Discord.AlternativeRoleID != "" {
						// 代替ロールが設定されている場合は、そのロールを付与する
						if err := executeWithRateLimit(func() error {
							return sess.GuildMemberRoleAdd(config.Discord.GuildID, item.ID, config.Discord.AlternativeRoleID)
						}, logger); err != nil {
							logger.Error("alternative role add failed", zap.Error(err), zap.String("username", item.Username))
						} else {
							logger.Info("alternative role added", zap.String("username", item.Username), zap.String("roleID", config.Discord.AlternativeRoleID))
							resultCh <- item
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

	if !config.Discord.DisableRoleRemoval {
		logger.Info("sync task completed",
			zap.Stringers("role add users", addRoleTargets),
			zap.Stringers("role remove users", removeRoleTargets),
		)
	} else {
		logger.Info("sync task completed (role removal disabled)",
			zap.Stringers("role add users", addRoleTargets),
			zap.Stringers("role remove candidates (not removed)", removeRoleTargets),
		)
	}

	if config.Discord.NotifyChannelID != "" {
		var notifyRemoveUsers []*discordgo.User
		var notifyAlternativeUsers []*discordgo.User
		if !config.Discord.DisableRoleRemoval {
			notifyRemoveUsers = removeRoleTargets
			notifyAlternativeUsers = alternativeRoleTargets
		}
		if len(addRoleTargets) != 0 || len(notifyRemoveUsers) != 0 || len(notifyAlternativeUsers) != 0 {
			err := PostResult(sess, config.Discord.NotifyChannelID, addRoleTargets, notifyRemoveUsers, notifyAlternativeUsers)
			if err != nil {
				logger.Error("post role modify info failed", zap.Error(err))
			}
		}
	}

	return nil
}

type commandRequest struct {
	Type        string
	Args        []string
	ChannelID   string
	Session     *discordgo.Session
	Interaction *discordgo.InteractionCreate
}

func setupCommandHandlers(sess *discordgo.Session, commandCh chan<- commandRequest, logger *zap.Logger) {
	// スラッシュコマンドハンドラー
	sess.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if i.Type != discordgo.InteractionApplicationCommand {
			return
		}

		data := i.ApplicationCommandData()
		var cmd commandRequest

		switch data.Name {
		case "discroak-interval":
			args := []string{}
			if len(data.Options) > 0 {
				args = append(args, data.Options[0].StringValue())
			}
			cmd = commandRequest{
				Type:        "interval",
				Args:        args,
				ChannelID:   i.ChannelID,
				Session:     s,
				Interaction: i,
			}
		case "discroak-status":
			cmd = commandRequest{
				Type:        "status",
				Args:        []string{},
				ChannelID:   i.ChannelID,
				Session:     s,
				Interaction: i,
			}
		case "discroak-help":
			cmd = commandRequest{
				Type:        "help",
				Args:        []string{},
				ChannelID:   i.ChannelID,
				Session:     s,
				Interaction: i,
			}
		default:
			return
		}

		select {
		case commandCh <- cmd:
			logger.Debug("slash command received", zap.String("type", cmd.Type), zap.Strings("args", cmd.Args))
		default:
			logger.Warn("command channel full, dropping slash command")
		}
	})
}

func handleCommand(cmd commandRequest, currentInterval *time.Duration, ticker *time.Ticker, logger *zap.Logger) error {
	switch cmd.Type {
	case "interval":
		return handleIntervalCommand(cmd, currentInterval, ticker, logger)
	case "status":
		return handleStatusCommand(cmd, *currentInterval, logger)
	case "help":
		return handleHelpCommand(cmd, logger)
	default:
		return sendResponse(cmd, "Unknown command. Use `/discroak-help` for available commands.")
	}
}

func handleIntervalCommand(cmd commandRequest, currentInterval *time.Duration, ticker *time.Ticker, logger *zap.Logger) error {
	if len(cmd.Args) == 0 {
		return sendResponse(cmd, fmt.Sprintf("Current interval: %v", *currentInterval))
	}

	intervalStr := cmd.Args[0]
	newInterval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return sendResponse(cmd, fmt.Sprintf("Invalid duration format: %s. Use format like '5m', '30s', '1h'", intervalStr))
	}

	if newInterval < time.Minute {
		return sendResponse(cmd, "Minimum interval is 1 minute.")
	}

	*currentInterval = newInterval
	ticker.Reset(newInterval)

	logger.Info("interval updated via discord command",
		zap.Duration("new_interval", newInterval),
		zap.String("channel", cmd.ChannelID))

	return sendResponse(cmd, fmt.Sprintf("Interval updated to: %v", newInterval))
}

func handleStatusCommand(cmd commandRequest, currentInterval time.Duration, _ *zap.Logger) error {
	message := fmt.Sprintf("Bot Status:\nCurrent sync interval: %v\nBot is running in daemon mode", currentInterval)
	return sendResponse(cmd, message)
}

func handleHelpCommand(cmd commandRequest, _ *zap.Logger) error {
	helpText := `Available slash commands:
- **/discroak-interval [duration]**: Set sync interval (e.g., '5m', '1h', '30s')
- **/discroak-status**: Show current bot status
- **/discroak-help**: Show this help message

Examples:
- /discroak-interval 10m
- /discroak-interval 2h
- /discroak-status`

	return sendResponse(cmd, helpText)
}

func sendResponse(cmd commandRequest, message string) error {
	if cmd.Interaction != nil {
		// スラッシュコマンドの場合
		return cmd.Session.InteractionRespond(cmd.Interaction.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: message,
			},
		})
	}
	// テキストコマンドの場合（現在は使用されない）
	_, err := cmd.Session.ChannelMessageSend(cmd.ChannelID, message)
	return err
}

func registerSlashCommands(sess *discordgo.Session, guildID string, logger *zap.Logger) error {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "discroak-interval",
			Description: "Set sync interval",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "duration",
					Description: "Duration (e.g., '5m', '1h', '30s')",
					Required:    false,
				},
			},
		},
		{
			Name:        "discroak-status",
			Description: "Show current bot status",
		},
		{
			Name:        "discroak-help",
			Description: "Show available commands",
		},
	}

	for _, cmd := range commands {
		_, err := sess.ApplicationCommandCreate(sess.State.User.ID, guildID, cmd)
		if err != nil {
			logger.Error("failed to create slash command", zap.String("name", cmd.Name), zap.Error(err))
			return err
		}
		logger.Info("registered slash command", zap.String("name", cmd.Name))
	}

	return nil
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return regexp.MustCompile(`(?i)(connection|websocket|network|timeout|closed|eof)`).MatchString(errStr)
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
	// safeSlice similar to s.Slice(0,length) but safe for out of index.
	safeSlice := func(s *utf8string.String, length int) string {
		if s.RuneCount() > length {
			return s.Slice(0, length)
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

func executeWithRateLimit(operation func() error, logger *zap.Logger) error {
	const maxRetries = 3
	const baseDelay = time.Millisecond * 500

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		// レート制限エラーの場合は待機時間を長くする
		if isRateLimitError(err) {
			delay := baseDelay * time.Duration(1<<attempt) * 2
			logger.Warn("rate limit hit, retrying",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
				zap.Duration("delay", delay))
			time.Sleep(delay)
			continue
		}

		// 他のエラーの場合は短い間隔でリトライ
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<attempt)
			logger.Warn("operation failed, retrying",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
				zap.Duration("delay", delay))
			time.Sleep(delay)
			continue
		}

		return err
	}

	return fmt.Errorf("operation failed after %d attempts", maxRetries)
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return regexp.MustCompile(`(?i)(rate limit|429|too many requests)`).MatchString(errStr)
}

func createDiscordSession(logger *zap.Logger, token string) (*discordgo.Session, error) {
	const maxRetries = 3
	const baseDelay = time.Second * 2

	var sess *discordgo.Session
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		sess, err = discordgo.New("Bot " + token)
		if err != nil {
			logger.Error("failed to create discord session",
				zap.Error(err),
				zap.Int("attempt", attempt+1))

			if attempt < maxRetries-1 {
				delay := baseDelay * time.Duration(1<<attempt)
				logger.Info("retrying discord session creation", zap.Duration("delay", delay))
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("failed to create discord session after %d attempts: %w", maxRetries, err)
		}

		err = sess.Open()
		if err != nil {
			logger.Error("failed to open discord connection",
				zap.Error(err),
				zap.Int("attempt", attempt+1))

			if attempt < maxRetries-1 {
				delay := baseDelay * time.Duration(1<<attempt)
				logger.Info("retrying discord connection", zap.Duration("delay", delay))
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("failed to open discord connection after %d attempts: %w", maxRetries, err)
		}

		logger.Info("discord session created and connected successfully", zap.Int("attempts", attempt+1))
		return sess, nil
	}

	return nil, err
}

func DiscordUserParse(usernameRaw string) (username, discriminator string, err error) {
	// Discord IDのみを受け付ける (数字であればOK)
	if discordIDRe.MatchString(usernameRaw) {
		return usernameRaw, "", nil
	}

	// Discord IDでない場合はエラーを返す
	return "", "", fmt.Errorf("input is not a valid Discord ID (must be numeric)")
}
