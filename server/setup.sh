#!/bin/sh
# v-Shell computer helper. Read it before you run it.
#   curl --proto '=https' -fsSL https://v-shell.cerebro.host/setup.sh | sh
# Checks SSH and tmux, then gives you a link (or QR code) to add this computer in v-Shell.
# It only checks, unless you say yes to installing Tailscale (Linux only, downloads from tailscale.com).
set -u
say() { printf '%s\n' "$*"; }
# Colour only on a terminal, and never when NO_COLOR is set.
g=''; y=''; r=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then g=$(printf '\033[32m'); y=$(printf '\033[33m'); r=$(printf '\033[0m'); fi
ok() { printf '  %s✓%s %s\n' "$g" "$r" "$*"; }
warn() { printf '  %s!%s %s\n' "$y" "$r" "$*"; }

# Ask a yes/no question on the terminal. No terminal (e.g. a non-interactive curl | sh) = No.
ask() {
  ans=""
  if (: </dev/tty) 2>/dev/null; then
    printf '%s ' "$1" >/dev/tty
    read -r ans </dev/tty 2>/dev/null || ans=""
  fi
  case "$ans" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

# Percent-encode one value for a link (keeps A-Z a-z 0-9 . _ ~ -).
urlenc() {
  printf '%s' "$1" | od -An -v -tu1 | awk '{ for (i = 1; i <= NF; i++) { c = $i
    if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 45 || c == 46 || c == 95 || c == 126) printf "%c", c
    else printf "%%%02X", c } }'
}
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# The v-Shell signature, only on a terminal at least 30 columns wide. Plain when NO_COLOR is set.
banner() {
  [ -t 1 ] || return 0
  cols=$(tput cols 2>/dev/null || echo 80)
  [ "${cols:-80}" -ge 30 ] 2>/dev/null || return 0
  printf '%s' "$g"
  cat <<'EOF'
         ___ _        _ _ 
__ _____/ __| |_  ___| | |
\ V /___\__ \ ' \/ -_) | |
 \_/    |___/_||_\___|_|_|
EOF
  printf '%s\n' "$r"
}

# Everything runs from main(), so a download cut off halfway runs nothing.
main() {
  user=$(id -un)
  os=$(uname -s)
  banner
  say ">_ v-Shell computer check ($os, user $user)"

  # 1. SSH
  if [ "$os" = "Darwin" ]; then
    if (systemsetup -getremotelogin 2>/dev/null | grep -qi ': on') || nc -z 127.0.0.1 22 2>/dev/null; then
      ok "Remote Login (SSH) is on"
    else
      warn "Remote Login is off. Turn it on: System Settings > General > Sharing > Remote Login"
    fi
  else
    if nc -z 127.0.0.1 22 2>/dev/null || ss -ltn 2>/dev/null | grep -q ':22 '; then ok "SSH is on (port 22)"
    else warn "SSH is off (nothing on port 22). Install it: sudo apt install openssh-server (Debian/Ubuntu)"; fi
  fi

  # 2. tmux (sessions that survive disconnects)
  PATH="$PATH:/opt/homebrew/bin:/usr/local/bin"
  if command -v tmux >/dev/null 2>&1; then ok "tmux $(tmux -V | cut -d' ' -f2) installed (sessions survive)"
  else
    warn "tmux not installed; sessions will end when the phone disconnects."
    if [ "$os" = "Darwin" ]; then say "    install: brew install tmux"; else say "    install: sudo apt install tmux   (or dnf/pacman)"; fi
  fi

  # 3. Home address (same Wi-Fi as your phone)
  home=""
  if [ "$os" = "Darwin" ]; then
    lhn=$(scutil --get LocalHostName 2>/dev/null)
    if [ -n "$lhn" ]; then home="$lhn.local"
    else home=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null); fi
  else
    home=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  if [ -n "$home" ]; then ok "At home: $home (same Wi-Fi as your phone)"
  else warn "Could not find this computer's home network address."; fi

  # 4. Away-from-home address (Tailscale, optional)
  ts=""
  if command -v tailscale >/dev/null 2>&1; then ts=tailscale
  elif [ "$os" = "Darwin" ] && [ -x /Applications/Tailscale.app/Contents/MacOS/Tailscale ]; then
    ts=/Applications/Tailscale.app/Contents/MacOS/Tailscale
  fi

  if [ -z "$ts" ] && [ "$os" != "Darwin" ]; then
    say ""
    say "  Optional: Tailscale lets your phone reach this computer from anywhere, with no router setup."
    if ask "  Install Tailscale so your phone can reach this computer from anywhere? It downloads from tailscale.com and needs sudo. [y/N]"; then
      sudo=""; [ "$(id -u)" = "0" ] || sudo=sudo
      tsf=$(mktemp "${TMPDIR:-/tmp}/tailscale-install.XXXXXX") || tsf=""
      if [ -n "$tsf" ] && curl -fsSL https://tailscale.com/install.sh -o "$tsf"; then
        sum=$(sha256 "$tsf")
        say "    Downloaded Tailscale's official installer from https://tailscale.com/install.sh"
        say "    Saved to: $tsf"
        say "    sha256:   ${sum:-unknown}"
        say "    Read it first if you like: less $tsf"
        if ask "  Run it now? [y/N]"; then
          if sh "$tsf"; then
            say "  Starting Tailscale. Open the link it prints and sign in."
            $sudo tailscale up && ts=tailscale
          else
            warn "Tailscale install failed. Nothing else was changed."
          fi
        else
          say "    Not run. Nothing was changed."
        fi
      else
        warn "Could not download the Tailscale installer. Nothing was changed."
      fi
      [ -n "$tsf" ] && rm -f "$tsf"
    else
      say "    Skipped. Run this again any time to add it."
    fi
  fi

  away=""
  if [ -n "$ts" ]; then
    away=$("$ts" ip -4 2>/dev/null | head -n1)
    if [ -n "$away" ]; then ok "Away from home (Tailscale): $away"
    elif [ "$os" = "Darwin" ]; then warn "Tailscale is installed but not connected. Open Tailscale, sign in, then run this again."
    else warn "Tailscale is installed but not connected. Run: sudo tailscale up, sign in, then run this again."; fi
  elif [ "$os" = "Darwin" ]; then
    say "  - Optional, to use it away from home: Tailscale isn't installed. Get it from the Mac App Store, sign in, then run this again."
  fi

  [ -n "$home$away" ] || { warn "Could not find an address for this computer."; exit 1; }

  # 5. Links for v-Shell
  name=$(hostname -s 2>/dev/null || hostname)
  # This computer's identity (SSH host key). v-Shell checks the first connection against it.
  fp=""
  if [ -r /etc/ssh/ssh_host_ed25519_key.pub ]; then
    fp=$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $2}')
    case "$fp" in SHA256:*) ;; *) fp="" ;; esac
  fi
  fpq=""; [ -n "$fp" ] && fpq="&fp=SHA256:$(urlenc "${fp#SHA256:}")"
  mklink() { printf 'vshell://add?host=%s&user=%s&port=22&name=%s%s' "$(urlenc "$1")" "$(urlenc "$user")" "$(urlenc "$name")" "$fpq"; }
  home_link=""; away_link=""
  [ -n "$home" ] && home_link=$(mklink "$home")
  [ -n "$away" ] && away_link=$(mklink "$away")
  link=${home_link:-$away_link}

  say ""
  [ -n "$fp" ] && say "Identity: $fp (v-Shell checks this automatically when you use this link)"
  say "On your iPhone: v-Shell > Add computer > Scan QR code (or Paste):"
  if command -v qrencode >/dev/null 2>&1; then
    if [ -n "$home_link" ]; then say ""; say "At home:"; say "  $home_link"; qrencode -t ANSIUTF8 "$home_link"; fi
    if [ -n "$away_link" ]; then say ""; say "Away from home (Tailscale):"; say "  $away_link"; qrencode -t ANSIUTF8 "$away_link"; fi
  else
    if [ -n "$home_link" ] && [ -n "$away_link" ]; then
      say "  At home:                     $home_link"
      say "  Away from home (Tailscale):  $away_link"
    else
      say "  $link"
    fi
    if [ "$os" = "Darwin" ] && command -v pbcopy >/dev/null 2>&1; then
      printf '%s' "$link" | pbcopy
      if [ -n "$home_link" ] && [ -n "$away_link" ]; then say "Link copied (At home). On your iPhone: v-Shell > Add computer > Paste."
      else say "Link copied. On your iPhone: v-Shell > Add computer > Paste."; fi
    fi
  fi
  say ""
  say "Then enter your password for '$user' once. v-Shell installs its own key and never stores the password."
}

main "$@"
