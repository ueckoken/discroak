# discroak

discroak is a discord role manager with keycloak attributes.

requires https://discord.com/developers/docs/resources/guild#list-guild-members

## 機能

- KeycloakのユーザーグループとDiscordロールの同期
- Discordトークンの自動再接続機能
- リアルタイム設定変更（Discordコマンド）
- レート制限対応

## 実行モード

### 常時実行モード（デフォルト）

```bash
./discroak
```

Discord接続を維持し、定期的にKeycloakとDiscordの同期を行います。

### 1回実行モード

```bash
RUN_ONCE=true ./discroak
```

従来通り、1回だけ同期処理を実行して終了します。

## 環境変数

| 変数名 | デフォルト値 | 説明 |
|--------|-------------|------|
| `RUN_ONCE` | `false` | `true`の場合、1回実行モードで動作 |
| `CHECK_INTERVAL` | `5m` | 常時実行モードでの同期間隔 |
| `STATE_FILE_PATH` | `./discroak_state.json` | 状態ファイルのパス |
| `DISCORD_TOKEN` | - | Discord Bot Token |
| `DISCORD_GUILD_ID` | - | Discord Guild ID |
| `DISCORD_ROLE_ID` | - | 管理対象のDiscord Role ID |
| `DISCORD_NOTIFY_CHANNEL_ID` | - | 通知チャンネルID（オプション） |
| `DISCORD_IGNORE_USER_IDS` | - | 無視するユーザーID（カンマ区切り） |
| `DISABLE_ROLE_REMOVAL` | `false` | ロール削除の無効化 |
| `ALTERNATIVE_ROLE_ID` | - | 代替ロールID（オプション） |

### パフォーマンス設定

| 変数名 | デフォルト値 | 説明 |
|--------|-------------|------|
| `MAX_WORKERS` | `2` | 並列処理の最大ワーカー数 |
| `MIN_INTERVAL_DURATION` | `1m` | コマンドで設定可能な最小同期間隔 |
| `COMMAND_CHANNEL_BUFFER` | `10` | コマンドチャンネルのバッファサイズ |

### リトライ設定

| 変数名 | デフォルト値 | 説明 |
|--------|-------------|------|
| `MAX_RETRIES` | `3` | 最大リトライ回数 |
| `BASE_RETRY_DELAY` | `500ms` | 基本リトライ間隔 |
| `CONNECTION_RETRY_DELAY` | `2s` | 接続リトライの基本間隔 |

### Keycloak設定

| 変数名 | 説明 |
|--------|------|
| `KEYCLOAK_ENDPOINT` | KeycloakエンドポイントURL |
| `KEYCLOAK_USERNAME` | Keycloak管理者ユーザー名 |
| `KEYCLOAK_PASSWORD` | Keycloak管理者パスワード |
| `KEYCLOAK_LOGIN_REALM` | ログイン用レルム |
| `KEYCLOAK_USER_REALM` | ユーザー管理レルム |
| `KEYCLOAK_ATTRS_KEY` | Discord ID を格納する属性キー |
| `KEYCLOAK_GROUP_PATH` | 対象グループのパス |

## Discordスラッシュコマンド

常時実行モードでは、以下のDiscordスラッシュコマンドが利用できます：

### `/discroak-interval [duration]`

同期間隔をリアルタイムで変更します。

```
/discroak-interval 10m    # 10分間隔に変更
/discroak-interval 2h     # 2時間間隔に変更
/discroak-interval 30s    # 30秒間隔に変更（最小間隔は設定可能）
```

### `/discroak-status`

現在のBot状態を表示します。

```
/discroak-status
```

### `/discroak-help`

利用可能なコマンドのヘルプを表示します。

```
/discroak-help
```

## 使用例

### 基本的な使用方法

```bash
# 環境変数を設定
export DISCORD_TOKEN="your_discord_bot_token"
export DISCORD_GUILD_ID="your_guild_id"
export DISCORD_ROLE_ID="your_role_id"
export KEYCLOAK_ENDPOINT="https://keycloak.example.com"
export KEYCLOAK_USERNAME="admin"
export KEYCLOAK_PASSWORD="admin_password"
export KEYCLOAK_LOGIN_REALM="master"
export KEYCLOAK_USER_REALM="your_realm"
export KEYCLOAK_ATTRS_KEY="discord_id"
export KEYCLOAK_GROUP_PATH="/members"

# 常時実行モードで開始（デフォルト5分間隔）
./discroak

# カスタム間隔で開始
CHECK_INTERVAL=30m ./discroak
```

### Docker使用例

```bash
docker run -d \
  -e DISCORD_TOKEN="your_token" \
  -e DISCORD_GUILD_ID="your_guild_id" \
  -e DISCORD_ROLE_ID="your_role_id" \
  -e KEYCLOAK_ENDPOINT="https://keycloak.example.com" \
  -e KEYCLOAK_USERNAME="admin" \
  -e KEYCLOAK_PASSWORD="admin_password" \
  -e KEYCLOAK_LOGIN_REALM="master" \
  -e KEYCLOAK_USER_REALM="your_realm" \
  -e KEYCLOAK_ATTRS_KEY="discord_id" \
  -e KEYCLOAK_GROUP_PATH="/members" \
  -e CHECK_INTERVAL="10m" \
  discroak:latest
```

## トラブルシューティング

### Discordトークンエラー

- `createDiscordSession`でエラーが発生する場合、トークンが正しいか確認してください
- 自動再接続機能により、一時的な接続エラーは自動的に復旧されます

### レート制限

- Discord API のレート制限に達した場合、自動的に待機して再試行します
- 同時実行数はデフォルトで2に制限されていますが、`MAX_WORKERS`で変更可能
- リトライ回数や間隔も環境変数で調整可能

### 設定の確認

Discordで`/discroak-status`を実行して、現在の設定を確認できます。

