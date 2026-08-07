#!/bin/bash
# Installer for claude-hookscanner.
#
# What this does, in order:
#   1. Generates an HMAC key and stores it somewhere NOT at a fixed,
#      predictable path -- either a directory you choose, or an
#      auto-generated random hidden directory under $HOME. The goal is
#      raising the bar against generic/opportunistic ("drive-by") npm/pip
#      supply-chain worms that hardcode a short list of well-known
#      filenames across many victims, not against a targeted attacker who
#      reads this repo and lists your ~/.claude/hooks directory by hand --
#      see the README's threat-model section for the honest version of
#      this claim.
#   2. Installs claude-hook-scan.sh / sign-hook.sh / ack-hook.sh to a bin
#      directory of your choice, and the PostToolUse reminder hook to
#      ~/.claude/hooks/, with the resolved key path baked into each
#      installed copy's *default* (an explicit CLAUDE_HOOK_HMAC_KEY env
#      var still overrides it -- nothing here removes that escape hatch).
#      Deliberately not exported via any shell rc file: that would just
#      trade one predictable "thing to grep for" (a fixed filename) for
#      another (a fixed env var name), which defeats the point.
#   3. Signs the reminder hook itself and offers to wire the PostToolUse
#      entry into ~/.claude/settings.json.
#   4. Runs a scan so you can see it working before you trust it.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NONINTERACTIVE=0
UNINSTALL=0
PURGE_STATE=0
KEY_DIR_ARG=""
BIN_DIR_ARG=""
WITH_CRON=""
CRON_TAG="# claude-hookscanner"

for arg in "$@"; do
  case "$arg" in
    --yes|-y) NONINTERACTIVE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge-state) PURGE_STATE=1 ;;
    --key-dir=*) KEY_DIR_ARG="${arg#*=}" ;;
    --bin-dir=*) BIN_DIR_ARG="${arg#*=}" ;;
    --with-cron=*) WITH_CRON="${arg#*=}" ;;
    --help|-h)
      echo "usage: install.sh [--yes] [--key-dir=PATH] [--bin-dir=PATH] [--with-cron=hourly|daily|off]"
      echo "       install.sh --uninstall [--yes] [--purge-state] [--key-dir=PATH] [--bin-dir=PATH]"
      exit 0
      ;;
  esac
done

say()  { echo "==> $*"; }
warn() { echo "!!  $*" >&2; }

# ── Uninstall ────────────────────────────────────────────────────────────────
# The key directory is intentionally not recorded anywhere -- see the
# install-time comment above the key-location prompt. To find it again for
# removal, this reads the same baked-in default back out of the reminder
# hook that install.sh itself relies on for idempotent re-runs: that file's
# location IS conventionally fixed (Claude Code has to find it there), so
# reading it back doesn't introduce any new exposure.
if [ "$UNINSTALL" = "1" ]; then
  HOOKS_DIR="$HOME/.claude/hooks"
  REMINDER_HOOK_DEST="$HOOKS_DIR/remind_sign_hook.py"

  KEY_FILE=""
  if [ -n "$KEY_DIR_ARG" ]; then
    KEY_FILE="$KEY_DIR_ARG/hmac_key"
  elif [ -f "$REMINDER_HOOK_DEST" ]; then
    KEY_FILE=$(grep -oE '^KEY_FILE_DEFAULT = "[^"]+"' "$REMINDER_HOOK_DEST" 2>/dev/null | sed -E 's/^KEY_FILE_DEFAULT = "(.*)"$/\1/' || true)
  fi
  if [ -z "$KEY_FILE" ] && [ "$NONINTERACTIVE" != "1" ]; then
    warn "Couldn't auto-detect the key location ($REMINDER_HOOK_DEST not found)."
    read -r -p "Key directory to remove (blank to skip): " manual_dir
    [ -n "$manual_dir" ] && KEY_FILE="$manual_dir/hmac_key"
  fi

  if [ -n "$BIN_DIR_ARG" ]; then
    BIN_DIR="$BIN_DIR_ARG"
  else
    found_bin="$(command -v claude-hook-scan.sh 2>/dev/null || true)"
    if [ -n "$found_bin" ]; then
      BIN_DIR="$(dirname "$found_bin")"
    else
      BIN_DIR="$HOME/.local/bin"
    fi
  fi

  # Only ever remove something we recognize as ours (carries the marker
  # our own install writes) -- never blind-delete by filename alone, in
  # case something unrelated landed at the same path.
  for f in sign-hook.sh ack-hook.sh claude-hook-scan.sh; do
    target="$BIN_DIR/$f"
    if [ -f "$target" ]; then
      if grep -q "_DEFAULT=" "$target" 2>/dev/null; then
        rm -f "$target"
        say "Removed $target"
      else
        warn "Skipped $target -- doesn't carry our marker, leaving it alone."
      fi
    fi
  done

  if [ -f "$REMINDER_HOOK_DEST" ]; then
    if grep -q "KEY_FILE_DEFAULT" "$REMINDER_HOOK_DEST" 2>/dev/null; then
      rm -f "$REMINDER_HOOK_DEST"
      say "Removed $REMINDER_HOOK_DEST"
    else
      warn "Skipped $REMINDER_HOOK_DEST -- doesn't carry our marker, leaving it alone."
    fi
  fi

  if [ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ]; then
    rm -f "$KEY_FILE"
    say "Removed key file $KEY_FILE"
    key_dir="$(dirname "$KEY_FILE")"
    base="$(basename "$key_dir")"
    # Only rmdir (harmlessly no-ops if non-empty) when it matches our own
    # auto-generated naming pattern directly under $HOME -- a
    # user-supplied --key-dir might be a directory they use for other
    # things, and we should never remove that out from under them.
    if [[ "$base" =~ ^\.[a-z]{6}$ ]] && [ "$(dirname "$key_dir")" = "$HOME" ]; then
      rmdir "$key_dir" 2>/dev/null && say "Removed empty key directory $key_dir" || true
    else
      say "Left directory $key_dir in place (custom path -- might hold other files)."
    fi
  elif [ -n "$KEY_FILE" ]; then
    warn "No key file at $KEY_FILE -- nothing to remove there."
  else
    warn "No key location known -- skipped. Remove it yourself if you remember where it is."
  fi

  SETTINGS="$HOME/.claude/settings.json"
  if [ -f "$SETTINGS" ] && command -v jq >/dev/null 2>&1; then
    has_entry=$(jq '[.hooks.PostToolUse[]?.hooks[]?.command // empty | select(contains("remind_sign_hook.py"))] | length > 0' "$SETTINGS" 2>/dev/null || echo false)
    if [ "$has_entry" = "true" ]; then
      cp "$SETTINGS" "$SETTINGS.bak.$(date +%s)"
      jq '.hooks.PostToolUse = ((.hooks.PostToolUse // []) | map(select(any(.hooks[]?; (.command // "") | contains("remind_sign_hook.py")) | not)))' \
        "$SETTINGS" > "$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS"
      say "Removed the PostToolUse entry from $SETTINGS (backup saved alongside it)."
    fi
  elif [ -f "$SETTINGS" ]; then
    warn "jq not found -- remove the PostToolUse entry referencing remind_sign_hook.py from $SETTINGS by hand."
  fi

  if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$CRON_TAG"; then
    # `grep -v` exits 1 when nothing matched to filter out (e.g. the tag
    # was the only line) -- that's a normal/expected outcome here, not an
    # error, so it must not be allowed to trip `set -e` and silently kill
    # the rest of the script (same footgun class as rand_dirname's
    # `head -c` fix above).
    ( crontab -l 2>/dev/null | grep -vF "$CRON_TAG" || true ) | crontab -
    say "Removed the cron entry."
  fi

  if [ "$PURGE_STATE" = "1" ]; then
    if [ "$(id -u)" = "0" ]; then
      state_dir_default="/var/log/claude-hookscanner"
    else
      state_dir_default="${XDG_STATE_HOME:-$HOME/.local/state}/claude-hookscanner"
    fi
    state_dir="${CLAUDE_HOOKSCANNER_STATE:-$state_dir_default}"
    if [ -d "$state_dir" ]; then
      rm -rf "$state_dir"
      say "Removed state dir $state_dir"
    fi
  else
    say "Left ack-list/scan history in place. Pass --purge-state to remove it too."
  fi

  say "Uninstall complete."
  exit 0
fi

# ── 1. Environment detection ────────────────────────────────────────────────
OS="unknown"
case "$(uname -s 2>/dev/null || echo unknown)" in
  Linux)  OS="linux" ;;
  Darwin) OS="macos" ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows-posix-layer" ;;
esac

SHELL_RC=""
case "${SHELL:-}" in
  */zsh)  [ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc" ;;
  */bash) [ -f "$HOME/.bashrc" ] && SHELL_RC="$HOME/.bashrc" ;;
  */fish) [ -f "$HOME/.config/fish/config.fish" ] && SHELL_RC="$HOME/.config/fish/config.fish" ;;
esac

say "Detected OS: $OS${SHELL_RC:+, shell rc: $SHELL_RC}"
if [ "$OS" = "unknown" ] || [ -z "$SHELL_RC" ]; then
  warn "Could not confidently detect your OS/shell config. This installer only"
  warn "writes files under paths you approve below -- it won't guess at your"
  warn "shell profile. If you want CLAUDE_HOOKSCANNER_STATE or"
  warn "CLAUDE_HOOKSCANNER_NOTIFY set persistently, add them to your shell's"
  warn "profile (or PowerShell \$PROFILE / setx on Windows) yourself -- see"
  warn "the README's Config Reference table for the exact variable names."
fi

command -v openssl >/dev/null 2>&1 || { warn "openssl is required and wasn't found."; exit 1; }
command -v jq      >/dev/null 2>&1 || warn "jq not found -- settings.json auto-merge (step 3) will be skipped; you'll get manual instructions instead."

# ── 2. Choose key location ──────────────────────────────────────────────────
rand_dirname() {
  # A bounded read (od -N6) terminates on its own -- unlike piping
  # /dev/urandom through `head -c N`, which sends SIGPIPE back up the
  # pipe when head cuts it off early and aborts the script under
  # `set -o pipefail`.
  od -An -N6 -tu1 /dev/urandom | tr -s ' ' '\n' | awk 'NF{printf "%c", 97 + ($1 % 26)}'
}

# Detect a prior install by reading the baked-in default out of the
# reminder hook, whose own location IS fixed/conventional (Claude Code has
# to find it there via settings.json, so that's not new exposure). This is
# what makes a --yes re-run idempotent without needing a separate pointer
# file at some other fixed location -- which would just reintroduce the
# exact "one predictable place to grep" problem the random directory
# exists to avoid.
EXISTING_KEY_FILE=""
REMINDER_HOOK_DEST="$HOME/.claude/hooks/remind_sign_hook.py"
if [ -f "$REMINDER_HOOK_DEST" ]; then
  EXISTING_KEY_FILE=$(grep -oE '^KEY_FILE_DEFAULT = "[^"]+"' "$REMINDER_HOOK_DEST" 2>/dev/null | sed -E 's/^KEY_FILE_DEFAULT = "(.*)"$/\1/' || true)
fi

if [ -n "$KEY_DIR_ARG" ]; then
  KEY_DIR="$KEY_DIR_ARG"
elif [ -n "$EXISTING_KEY_FILE" ] && [ -f "$EXISTING_KEY_FILE" ]; then
  KEY_DIR="$(dirname "$EXISTING_KEY_FILE")"
  say "Existing install detected -- reusing key at $EXISTING_KEY_FILE"
  say "(pass --key-dir=... to rotate to a new location instead)"
elif [ "$NONINTERACTIVE" = "1" ]; then
  KEY_DIR="$HOME/.$(rand_dirname)"
else
  echo
  echo "Where should the HMAC key live?"
  echo "  1) Auto-generate a random hidden directory under \$HOME (recommended)"
  echo "  2) A path you specify"
  read -r -p "Choice [1]: " choice
  case "${choice:-1}" in
    2)
      read -r -p "Directory for the key: " KEY_DIR
      ;;
    *)
      KEY_DIR="$HOME/.$(rand_dirname)"
      say "Generated: $KEY_DIR"
      ;;
  esac
fi

KEY_FILE="$KEY_DIR/hmac_key"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

if [ -f "$KEY_FILE" ]; then
  warn "A key already exists at $KEY_FILE -- leaving it in place (re-running"
  warn "install.sh doesn't rotate keys; delete it yourself first if you want"
  warn "a fresh one, but you'll need to re-sign every hook afterward)."
else
  openssl rand -hex 32 > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  say "Key generated at $KEY_FILE (permissions 600)"
fi

# ── 3. Choose bin dir, install scripts ──────────────────────────────────────
if [ -n "$BIN_DIR_ARG" ]; then
  BIN_DIR="$BIN_DIR_ARG"
elif [ "$NONINTERACTIVE" = "1" ]; then
  BIN_DIR="$HOME/.local/bin"
else
  read -r -p "Install claude-hook-scan.sh / sign-hook.sh / ack-hook.sh to [$HOME/.local/bin]: " BIN_DIR
  BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
fi
mkdir -p "$BIN_DIR"

HOOKS_DIR="$HOME/.claude/hooks"
mkdir -p "$HOOKS_DIR"

install_templated() {
  # $1 = source file  $2 = dest file
  local src="$1" dest="$2"
  cp "$src" "$dest"
  chmod 755 "$dest"
  # Rewrite the line immediately after the INSTALL_DEFAULT_KEY_FILE marker
  # to point at the resolved key path, for every script that carries one.
  case "$dest" in
    *.py)
      sed -i.bak "s|^KEY_FILE_DEFAULT = .*|KEY_FILE_DEFAULT = \"$KEY_FILE\"|" "$dest"
      ;;
    *.sh)
      sed -i.bak \
        -e "s|^KEY_FILE_DEFAULT=.*|KEY_FILE_DEFAULT=\"$KEY_FILE\"|" \
        -e "s|^HMAC_KEY_FILE_DEFAULT=.*|HMAC_KEY_FILE_DEFAULT=\"$KEY_FILE\"|" \
        "$dest"
      ;;
  esac
  rm -f "$dest.bak"
}

install_templated "$REPO_DIR/bin/sign-hook.sh"       "$BIN_DIR/sign-hook.sh"
install_templated "$REPO_DIR/bin/ack-hook.sh"         "$BIN_DIR/ack-hook.sh"
install_templated "$REPO_DIR/bin/claude-hook-scan.sh" "$BIN_DIR/claude-hook-scan.sh"
install_templated "$REPO_DIR/hooks/remind_sign_hook.py" "$HOOKS_DIR/remind_sign_hook.py"

say "Installed CLI tools to $BIN_DIR"
say "Installed reminder hook to $HOOKS_DIR/remind_sign_hook.py"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH. Add it, or call the tools by full path." ;;
esac

# ── 4. Sign the reminder hook itself ────────────────────────────────────────
"$BIN_DIR/sign-hook.sh" "$HOOKS_DIR/remind_sign_hook.py"

# ── 5. Wire settings.json ───────────────────────────────────────────────────
SETTINGS="$HOME/.claude/settings.json"
POSTTOOLUSE_ENTRY=$(cat <<EOF
{
  "matcher": "Edit|Write|MultiEdit",
  "hooks": [
    { "type": "command", "command": "python3 $HOOKS_DIR/remind_sign_hook.py", "timeout": 10 }
  ]
}
EOF
)

wire_manually() {
  echo
  say "Add this to the \"hooks\" -> \"PostToolUse\" array in $SETTINGS:"
  echo "$POSTTOOLUSE_ENTRY"
}

if ! command -v jq >/dev/null 2>&1; then
  wire_manually
elif [ ! -f "$SETTINGS" ]; then
  mkdir -p "$(dirname "$SETTINGS")"
  jq -n --argjson entry "$POSTTOOLUSE_ENTRY" '{hooks: {PostToolUse: [$entry]}}' > "$SETTINGS"
  say "Created $SETTINGS with the PostToolUse entry."
else
  already=$(jq '[.hooks.PostToolUse[]?.hooks[]?.command // empty | select(contains("remind_sign_hook.py"))] | length > 0' "$SETTINGS" 2>/dev/null || echo false)
  if [ "$already" = "true" ]; then
    say "$SETTINGS already references remind_sign_hook.py -- leaving it as-is."
  elif [ "$NONINTERACTIVE" = "1" ]; then
    wire_manually
  else
    read -r -p "Merge the PostToolUse entry into $SETTINGS automatically (backup made first)? [Y/n] " ans
    if [ "${ans:-Y}" != "${ans#[Nn]}" ]; then
      wire_manually
    else
      cp "$SETTINGS" "$SETTINGS.bak.$(date +%s)"
      jq --argjson entry "$POSTTOOLUSE_ENTRY" \
        '.hooks.PostToolUse = ((.hooks.PostToolUse // []) + [$entry])' \
        "$SETTINGS" > "$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS"
      say "Merged into $SETTINGS (backup saved alongside it)."
    fi
  fi
fi

# ── 6. Optional periodic scan (cron) ────────────────────────────────────────
# The reminder hook only catches hooks written *through* a Claude Code
# session -- a hook planted some other way (a raw `npm install` run
# outside a session, or anything dropped directly onto disk) still needs
# an actual periodic scan to be caught at all. Skippable/off by default
# under --yes, since adding a cron entry is a bigger footprint than
# anything else this installer does and shouldn't happen silently.
if [ "$(id -u)" = "0" ]; then
  cron_state_dir_default="/var/log/claude-hookscanner"
else
  cron_state_dir_default="${XDG_STATE_HOME:-$HOME/.local/state}/claude-hookscanner"
fi
CRON_SCHEDULE=""
case "$WITH_CRON" in
  hourly) CRON_SCHEDULE="0 * * * *" ;;
  daily)  CRON_SCHEDULE="0 3 * * *" ;;
  off|"") ;;
  *) warn "Unrecognized --with-cron value '$WITH_CRON' -- expected hourly, daily, or off. Skipping cron." ;;
esac

if [ -z "$CRON_SCHEDULE" ] && [ -z "$WITH_CRON" ] && [ "$NONINTERACTIVE" != "1" ] && command -v crontab >/dev/null 2>&1; then
  echo
  echo "Add a cron entry to scan periodically, catching hooks planted"
  echo "outside a Claude Code session (the reminder hook alone won't see those)?"
  echo "  1) Hourly"
  echo "  2) Daily"
  echo "  3) Skip"
  read -r -p "Choice [3]: " cron_choice
  case "${cron_choice:-3}" in
    1) CRON_SCHEDULE="0 * * * *" ;;
    2) CRON_SCHEDULE="0 3 * * *" ;;
    *) ;;
  esac
fi

if [ -n "$CRON_SCHEDULE" ] && command -v crontab >/dev/null 2>&1; then
  mkdir -p "$cron_state_dir_default"
  cron_line="$CRON_SCHEDULE $BIN_DIR/claude-hook-scan.sh >> $cron_state_dir_default/scan.log 2>&1 $CRON_TAG"
  # Same `grep -v` / set -e footgun as above -- empty or tag-free existing
  # crontab is the common case, not an error.
  ( crontab -l 2>/dev/null | grep -vF "$CRON_TAG" || true; echo "$cron_line" ) | crontab -
  say "Cron entry added: $cron_line"
elif [ -n "$CRON_SCHEDULE" ]; then
  warn "No crontab command found -- couldn't add periodic scanning. Add it yourself, see the README's cron example."
fi

# ── 7. Show it working ───────────────────────────────────────────────────────
echo
say "Running a scan so you can see it working:"
CLAUDE_HOOK_HMAC_KEY="$KEY_FILE" "$BIN_DIR/claude-hook-scan.sh" || true

echo
say "Done. Key stored at: $KEY_FILE"
say "That path isn't written to any shell rc file or env var by default --"
say "the installed scripts have it baked in as their default. Write it down"
say "somewhere you control if you'll need it for a manual recovery later."
