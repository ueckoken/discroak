# Discroak - Claude Code Developer Guide

## Project Overview

**Discroak** is a Discord role manager that synchronizes user roles between Keycloak (identity provider) and Discord servers. It's written in Go and designed to run as either a one-time sync tool or a persistent daemon with real-time Discord integration.

### Core Functionality
- Synchronizes Keycloak user groups with Discord roles
- Automatic Discord token reconnection and resilience
- Real-time configuration changes via Discord slash commands
- Rate limiting and retry mechanisms for API calls
- State persistence to optimize sync operations

## Architecture

### Tech Stack
- **Language**: Go 1.20+ (currently using 1.23.4 via aqua)
- **Key Dependencies**:
  - `github.com/bwmarrin/discordgo` - Discord API client
  - `github.com/Nerzal/gocloak/v12` - Keycloak API client
  - `github.com/vrischmann/envconfig` - Environment configuration
  - `go.uber.org/zap` - Structured logging
  - `github.com/samber/lo` - Functional utilities

### Application Structure
- **Single binary**: All code is in `main.go` (~940 lines)
- **Entry point**: `main()` function handles both daemon and one-time modes
- **Configuration**: Environment-based using `envconfig` tags
- **State management**: JSON file persistence (`discroak_state.json`)

### Core Components
1. **Configuration Management** (`Conf` struct)
2. **Keycloak Integration** (`fetchKeycloakUsers`, `getKeycloakCircleMembers`)
3. **Discord Integration** (session management, role operations, slash commands)
4. **State Persistence** (`SaveState`, `LoadState`, difference detection)
5. **Worker Pool** (concurrent role operations with rate limiting)
6. **Command System** (Discord slash command handlers)

## Development Commands

### Prerequisites
- Install [aqua](https://aquaproj.github.io/) for tool management
- Run `aqua install` to install Go and golangci-lint

### Build Commands
```bash
# Build the application
make build

# Build with specific version
make build VERSION=v1.0.0

# Test the application
make test

# Run linting (via CI or aqua)
golangci-lint run
```

### Running the Application

#### Environment Setup
Create a `.env` file or set environment variables (see `ENVIRONMENT_VARIABLES.md` for complete list):

```bash
# Discord Configuration
export DISCORD_TOKEN="your_bot_token"
export DISCORD_GUILD_ID="your_guild_id"
export DISCORD_ROLE_ID="role_to_manage"
export DISCORD_NOTIFY_CHANNEL_ID="notification_channel_id"  # optional

# Keycloak Configuration
export KEYCLOAK_ENDPOINT="https://keycloak.example.com"
export KEYCLOAK_USERNAME="admin"
export KEYCLOAK_PASSWORD="admin_password"
export KEYCLOAK_LOGIN_REALM="master"
export KEYCLOAK_USER_REALM="your_realm"
export KEYCLOAK_ATTRS_KEY="discord_id"
export KEYCLOAK_GROUP_PATH="/members"
```

#### Execution Modes
```bash
# Daemon mode (default) - runs continuously with Discord integration
./discroak

# One-time mode - single sync operation
RUN_ONCE=true ./discroak

# Custom sync interval
CHECK_INTERVAL=10m ./discroak
```

### Docker Development
```bash
# Local development with docker-compose
docker-compose up -d  # Starts app + Keycloak + MySQL

# Build production image
docker build -t discroak .

# Run with environment file
docker run --env-file .env discroak
```

## Configuration Reference

### Runtime Modes
- **Daemon Mode** (default): Maintains Discord connection, periodic sync, supports slash commands
- **One-time Mode** (`RUN_ONCE=true`): Single sync operation then exit

### Key Configuration Options

#### Performance Tuning
- `MAX_WORKERS=2` - Concurrent role operations
- `CHECK_INTERVAL=5m` - Sync frequency in daemon mode
- `MIN_INTERVAL_DURATION=1m` - Minimum allowed interval via commands

#### Resilience Settings
- `MAX_RETRIES=3` - API call retry attempts
- `BASE_RETRY_DELAY=500ms` - Base retry delay
- `CONNECTION_RETRY_DELAY=2s` - Discord reconnection delay

#### Feature Flags
- `DISABLE_ROLE_REMOVAL=false` - Disable role removal operations
- `ALTERNATIVE_ROLE_ID` - Role to assign when removing primary role
- `DISCORD_IGNORE_USER_IDS` - Comma-separated user IDs to skip

### Discord Slash Commands (Daemon Mode Only)
- `/discroak-interval [duration]` - Change sync interval
- `/discroak-status` - Show bot status
- `/discroak-help` - Show available commands

## Development Guidelines

### Code Structure
- **Single file approach**: All logic is in `main.go` for simplicity
- **Environment-driven**: All configuration via environment variables
- **Functional style**: Heavy use of `lo` library for data transformations
- **Structured logging**: Use `zap.Logger` for all logging

### Key Functions to Understand
1. `main()` - Entry point, handles mode selection
2. `runSyncWithSession()` - Core sync logic
3. `fetchKeycloakUsers()` - Keycloak API interaction
4. `executeWithRateLimit()` - Rate limiting wrapper
5. `createDiscordSession()` - Discord connection with retries
6. `setupCommandHandlers()` - Slash command routing

### Testing
- Tests are in `main_test.go`
- Focus on configuration parsing and message formatting
- Run tests with `make test`

### State Management
- Application maintains state in `discroak_state.json`
- Only processes changes to minimize API calls
- State includes previous Keycloak users and Discord role members

## CI/CD Pipeline

### GitHub Actions
- **CI** (`.github/workflows/ci.yaml`): Runs on every push
  - Go build and test
  - golangci-lint
- **Release** (`.github/workflows/release.yaml`): Runs on tags
  - Multi-platform builds (Linux, Windows, macOS)
  - Docker images for amd64/arm64
  - Uses GoReleaser

### Release Process
1. Create and push a git tag: `git tag v1.0.0 && git push origin v1.0.0`
2. GitHub Actions automatically builds and releases
3. Artifacts published to GitHub Container Registry (`ghcr.io/ueckoken/discroak`)

### Tool Management
- **aqua** (`aqua.yaml`): Manages Go and golangci-lint versions
- **Renovate** (`renovate.json`): Automated dependency updates
- **GoReleaser** (`.goreleaser.yaml`): Cross-platform build and release

## Common Development Tasks

### Adding New Configuration
1. Add field to appropriate `Conf` struct with `envconfig` tag
2. Update `ENVIRONMENT_VARIABLES.md`
3. Add test case in `TestParseConfig`
4. Update documentation

### Modifying Sync Logic
- Main sync logic is in `runSyncWithSession()`
- Consider state persistence impact
- Test with both daemon and one-time modes
- Ensure proper error handling and logging

### Adding Discord Commands
1. Add command definition in `registerSlashCommands()`
2. Add handler case in `setupCommandHandlers()`
3. Implement handler function following existing patterns
4. Update documentation

### Debugging
- Set `LOG_LEVEL=debug` for verbose logging
- Use `LOG_IS_DEVELOPMENT=true` for human-readable logs
- Check `discroak_state.json` for state persistence issues
- Monitor Discord API rate limits in logs

## Troubleshooting

### Common Issues
1. **Discord Token Errors**: Verify bot permissions and token validity
2. **Keycloak Connection**: Check endpoint URL and admin credentials
3. **Rate Limiting**: Adjust `MAX_WORKERS` and retry settings
4. **State File Issues**: Delete `discroak_state.json` to reset state

### Development Environment
- Use `docker-compose up` for local Keycloak instance
- Test with minimal Discord server setup
- Monitor logs for API errors and rate limit warnings

This guide provides the essential information needed for effective development in this codebase. The application is designed for simplicity and reliability, with comprehensive configuration options and robust error handling.