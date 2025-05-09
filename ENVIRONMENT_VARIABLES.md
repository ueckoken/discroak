# 環境変数ドキュメント

このドキュメントは、compose.yamlで設定されている環境変数の一覧と説明をまとめたものです。また、main.goのenvconfigタグで設定されている環境変数も含みます。

## appサービスの環境変数

| 変数名                 | 説明                             | デフォルト値 / 備考               |
|------------------------|--------------------------------|---------------------------------|
| LOG_LEVEL              | ログの出力レベル               | debug                           |
| LOG_IS_DEVELOPMENT     | 開発モードかどうかのフラグ     | true                            |
| KEYCLOAK_ENDPOINT      | KeycloakのエンドポイントURL   | http://keycloak:8080            |
| KEYCLOAK_USERNAME      | Keycloakのユーザー名           | admin                          |
| KEYCLOAK_PASSWORD      | Keycloakのパスワード           | admin                          |
| KEYCLOAK_LOGIN_REALM   | Keycloakのログイン用レルム     | master                         |
| KEYCLOAK_USER_REALM    | Keycloakのユーザーレルム       | (未設定)                       |
| KEYCLOAK_ATTRS_KEY     | Keycloak属性のキー             | discord-username               |
| KEYCLOAK_GROUP_PATH    | Keycloakグループパス           | (未設定)                       |
| DISCORD_TOKEN          | Discordのトークン              | (未設定)                       |
| DISCORD_GUILD_ID       | DiscordギルドID               | (未設定)                       |
| DISCORD_ROLE_ID        | DiscordロールID               | (未設定)                       |
| DISCORD_IGNORE_USER_IDS | Discordで無視するユーザーIDリスト | "1234,4567"                    |

## main.goで設定されている環境変数

| 変数名                 | 説明                             | デフォルト値 / 備考               |
|------------------------|--------------------------------|---------------------------------|
| LOG_LEVEL              | ログの出力レベル               | info (envconfigデフォルト)       |
| LOG_IS_DEVELOPMENT     | 開発モードかどうかのフラグ     | false (envconfigデフォルト)      |
| DISCORD_NOTIFY_CHANNEL_ID | Discordの通知チャンネルID      | (optional)                      |
| DISCORD_IGNORE_USER_IDS | Discordで無視するユーザーIDリスト | (optional)                      |
| DISABLE_ROLE_REMOVAL   | ロール削除機能を無効化するフラグ | false (optional, envconfigデフォルト) |
| ALTERNATIVE_ROLE_ID    | ロール削除時に代わりに付与するロールID | (optional)                      |
| STATE_FILE_PATH        | 状態を保存するファイルのパス     | ./discroak_state.json (envconfigデフォルト) |

## keycloakサービスの環境変数

| 変数名                 | 説明                             | デフォルト値 / 備考               |
|------------------------|--------------------------------|---------------------------------|
| KEYCLOAK_ADMIN         | Keycloak管理者ユーザー名       | admin                          |
| KEYCLOAK_ADMIN_PASSWORD | Keycloak管理者パスワード       | admin                          |
| KC_DB                  | Keycloakで使用するDBタイプ     | mysql                          |
| KC_DB_URL_DATABASE     | KeycloakのDB名                 | keycloak                       |
| KC_DB_URL_HOST         | KeycloakのDBホスト             | keycloak-db                    |
| KC_DB_USERNAME         | KeycloakのDBユーザー名         | root                           |
| KC_DB_PASSWORD         | KeycloakのDBパスワード         | password                       |

## keycloak-dbサービスの環境変数

| 変数名                 | 説明                             | デフォルト値 / 備考               |
|------------------------|--------------------------------|---------------------------------|
| MYSQL_ROOT_PASSWORD     | MySQLのrootパスワード           | password                       |
| MYSQL_DATABASE         | MySQLのデータベース名           | keycloak                       |
| MYSQL_USER             | MySQLのユーザー名               | keycloak                       |
| MYSQL_PASSWORD         | MySQLのユーザーパスワード       | password                       |

</content>
