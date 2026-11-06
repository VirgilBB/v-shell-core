import Foundation

public enum ShellQuote {
    /// POSIX single-quote escaping: abc'd -> 'abc'\''d'
    public static func quote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    /// Text typed into the terminal WITHOUT pressing Return: control characters (CR, LF, Ctrl-keys,
    /// ESC, DEL) are keypresses at a shell, so they are removed. A snippet that says "never presses
    /// Return" must not carry its own.
    public static func typeOnly(_ s: String) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7F && !(0x80...0x9F).contains($0.value) }))
    }
}

/// Builds the remote commands the app runs. Kept pure so they are unit tested.
public enum RemoteCommands {
    /// Idempotently adds a public key line to ~/.ssh/authorized_keys with correct perms.
    /// Prints VSHELL_KEY_OK on success so the app can verify.
    public static func installAuthorizedKey(_ publicKeyLine: String) -> String {
        let k = ShellQuote.quote(publicKeyLine.trimmingCharacters(in: .whitespacesAndNewlines))
        return "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
            + "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && "
            + "(grep -qxF \(k) ~/.ssh/authorized_keys || printf '%s\\n' \(k) >> ~/.ssh/authorized_keys) && "
            + "echo VSHELL_KEY_OK"
    }

    /// tmux session names: letters, digits, - and _ only.
    public static func sanitizeSessionName(_ name: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        let s = String(name.filter { allowed.contains($0) })
        return s.isEmpty ? "vshell" : String(s.prefix(32))
    }

    /// Attach-or-create tmux; if tmux is missing, a normal login shell.
    /// Sent as the exec command so a reconnect lands back in the same session.
    /// Homebrew paths are added because macOS non-interactive exec has a minimal PATH.
    /// Attach or create. With `plain` (default) and no tmux config of the user's own, the session
    /// hides tmux's status line and turns mouse on (scrollback works by swiping). Session-scoped
    /// options only: the user's files and global tmux settings are never touched.
    /// `startup` (e.g. `cd ~/code/app && claude`) runs only when the session is CREATED: with -A
    /// tmux ignores the command when the session already exists, so a reconnect never types it into
    /// a running agent. A shell follows it so the session survives the program exiting.
    public static func tmuxAttach(session: String, plain: Bool = true, startup: String = "") -> String {
        let s = sanitizeSessionName(session)
        let first = startup.trimmingCharacters(in: .whitespacesAndNewlines)
        let attach = first.isEmpty ? "tmux new-session -A -s \(s)"
            : "tmux new-session -A -s \(s) " + ShellQuote.quote(first + "; exec \"${SHELL:-/bin/sh}\" -l")
        let start = plain
            ? "if [ -f ~/.tmux.conf ] || [ -f \"${XDG_CONFIG_HOME:-$HOME/.config}/tmux/tmux.conf\" ]; then exec \(attach); "
              + "else exec \(attach) \\; set-option status off \\; set-option mouse on; fi"
            : "exec \(attach)"
        return "PATH=\"$PATH:/opt/homebrew/bin:/usr/local/bin\"; "
            + "if command -v tmux >/dev/null 2>&1; then \(start); "
            + "else echo 'v-Shell: tmux not found, opening a normal shell (sessions will not survive disconnects).'; "
            + "exec \"${SHELL:-/bin/sh}\" -l; fi"
    }
}
