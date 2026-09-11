# Shroodler Discord Bot

Standalone Discord bot that wraps the [`shroodler`](https://github.com/Fantastic-Fanta/Shroodler) CLI. It does **not** import Shroodler as a Python library — it runs the `shroodler` binary as a subprocess.

Install Shroodler separately (`pip install` or `git clone` + `pip install -e .`) and make sure it is on `PATH`, or set `SHROODLER_BIN` to the binary path. See [Fantastic-Fanta/Shroodler](https://github.com/Fantastic-Fanta/Shroodler) for installation instructions.

## Prerequisites

- Python 3.11+
- Shroodler installed and available on `PATH` (or `SHROODLER_BIN`)
- A Discord bot token with the `applications.commands` and `bot` OAuth2 scopes
- Privileged / gateway intents enabled for the bot:
  - Message Content
  - Guilds
  - Guild Messages
- The bot invited to the server whose ID you put in `DISCORD_GUILD_ID`

Shroodler itself may need API keys or other environment variables; those should be present in the same environment the bot runs in so the subprocess can inherit them.

## Create the Discord bot

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) and create an application.
2. Open **Bot**, click **Reset Token** / **Copy**, and save the token as `DISCORD_TOKEN`.
3. Under **Privileged Gateway Intents**, enable **Message Content Intent**.
4. Open **Installation**. Under **Installation Contexts** enable **User Install** (and **Guild Install** if you also want to add it to servers). This is what makes it work as a personal app you can use in any DM.
5. Still under **Installation**, set the default install settings: for **Guild Install** use scopes `bot` + `applications.commands` with permissions to send messages, send messages in threads, create public threads, attach files, and embed links; for **User Install** use scope `applications.commands`. Use the generated install link to add the app to your account and/or a server.
6. Under **Bot → Privileged Gateway Intents**, enable **Message Content Intent**.
7. (Optional) Enable Developer Mode in Discord (User Settings → Advanced) to copy IDs. Copy your server ID → `DISCORD_GUILD_ID` and/or your user ID(s) → `AUTHORIZED_USER_IDS`.

### Authorization

Scans are gated so the bot is never open to anyone:

- **`DISCORD_GUILD_ID`** — members of this server are authorized (works in the server and in their DMs).
- **`AUTHORIZED_USER_IDS`** — comma-separated user IDs authorized anywhere the app is installed. Use this for a user-installed app that has no shared server.

Set at least one; the bot refuses to start with neither.

Slash commands are registered globally at startup, so `/pentest`, `/status`, and `/cancel` work in servers, in DMs, and as a user-installed app. Discord can take a few minutes to refresh the picker after a restart.

**User-install limitation:** a user-installed app can only stream its live output where it can post freely — its **DMs** and servers where the bot itself is a member. In a server where it is only user-installed (not added as a bot), Discord restricts it to short-lived interaction replies, so long scans should be run from a DM or from a server the bot has been added to.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env with your token and guild ID
python bot.py
```

On ready you should see:

```text
shroodler-bot ready. shroodler at: /path/to/shroodler
```

If the binary is missing, `/pentest` replies that Shroodler is not installed.

## Commands

| Command | Who | What |
| --- | --- | --- |
| `/pentest <target> [profile] [session]` | Home server members | Run `shroodler agent` immediately
| `/status` | Home server members | Private list of running scans |
| `/cancel <job_id>` | Home server members | SIGTERM the subprocess (SIGKILL after 5s) |

`profile` is `safe`, `balanced` (default), or `aggressive`.

`target` must be `http://` or `https://` with a real hostname. Localhost, loopback, RFC1918, link-local, `.local` / `.localhost` / `.internal`, and userinfo tricks are rejected.

Live findings, `/status`, and the final summary use Discord Components V2 (not embeds). `/pentest` is a single message that evolves in place: running, then the finished summary with the markdown report and full debug log attached. In guild text channels the bot also opens a thread on that message for the verbose live log. In DMs (and if thread creation fails) there is no thread; the original message stays the live status and shows a short recent-output preview while the scan runs. Failed, cancelled, and timed-out scans edit that same message to an error/cancelled summary instead of posting a new channel dump.

Slash commands are registered globally so they work in servers, in DMs, and as a user-installed app. Global command updates can take a few minutes to appear. Commands are limited to members of `DISCORD_GUILD_ID` and/or the IDs in `AUTHORIZED_USER_IDS`, including when used in a DM.

## Authenticated scans

Do not send passwords or cookies through Discord. Log in with a real browser (SSO, MFA, SPA overlays), export the session on the **bot host**, and let `/pentest` pick it automatically when the folder name matches the target hostname. Pass `session` to override (or force `unauthenticated`).

Default directory: `~/.shroodler/bot-sessions` (`SESSIONS_DIR`).

```bash
# Chrome started with --remote-debugging-port=9222
shroodler session-export --cdp http://127.0.0.1:9222 \
  --origin https://app.example.com -o ~/.shroodler/bot-sessions/app.example.com/owner.json

# Optional second account for IDOR / authz-diff
shroodler session-export --cdp http://127.0.0.1:9223 \
  --origin https://app.example.com -o ~/.shroodler/bot-sessions/app.example.com/peer.json
```

Layout (either style works):

```text
~/.shroodler/bot-sessions/
  app.example.com/
    owner.json          # Playwright storageState or cookie jar
    peer.json           # optional
    login.json          # optional login recipe, for re-auth on 401
    peer-login.json     # optional
    hosts.txt           # optional; one hostname glob per line
  lab-admin/
    owner.json          # named profile, shown for every target
  other.example.com.owner.json
  other.example.com.peer.json
```

A folder named like a hostname is auto-selected when `/pentest` targets that host (or a subdomain). Named folders without a dot are listed but not auto-selected. A matching login recipe is passed as `--login-recipe` so Shroodler can re-auth mid-scan; jars are `--higher-priv-jar` / `--lower-priv-jar`.

Leave the dropdown on **Unauthenticated** for a public scan.

If the site is a simple form login and you want Shroodler to POST credentials itself, put a recipe on disk (not in Discord) and reference env vars:

```json
{
  "url": "https://example.com/login",
  "method": "POST",
  "content_type": "form",
  "fields": {
    "username": "${SHROODLER_USER}",
    "password": "${SHROODLER_PASS}"
  }
}
```

## Docker

```bash
docker build -t shroodler-bot .
docker run --env-file .env \
  -v /usr/local/bin/shroodler:/usr/local/bin/shroodler \
  shroodler-bot
```

Mounting a single binary often is not enough if Shroodler is a Python entry point with its own dependencies. Prefer installing Shroodler in the image, or run the bot on the host where `shroodler` already works.

## Configuration

See `.env.example`. Notable knobs:

- `SHROODLER_BIN` — binary name or path (default `shroodler`). The bot also looks in `~/.local/bin` if the name is not on `PATH`.
- `SHROODLER_EXTRA_FLAGS` — extra flags appended to every `shroodler agent` run (parsed with `shlex.split`, never via a shell)
- `MAX_CONCURRENT_SCANS` — new scans are rejected while this many are running
- `SCAN_TIMEOUT_SECONDS` — hard kill after this many seconds (default 1800 = 30 minutes)
- `REPORT_DIR` — per-job `state.json` and `report.md`
- `SESSIONS_DIR` — host-side cookie jars and login recipes (default `~/.shroodler/bot-sessions`)

Jobs live in memory only. Restarting the bot forgets in-flight scans (child processes are cancelled on SIGINT/SIGTERM).

## Security

The bot validates RFC1918 ranges, loopback, link-local, and a few internal TLDs, but **operators are responsible for ensuring every target is authorized**. Running `/pentest` is the authorization. Do not expose it to untrusted users.
