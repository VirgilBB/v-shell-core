# v-Shell patches to swift-nio-ssh 0.15.0

Vendored from https://github.com/apple/swift-nio-ssh tag 0.15.0 (Apache-2.0, LICENSE.txt
kept). Tests, benchmarks and CI scripts were removed. Every change is marked `v-Shell patch`.

1. Client keyboard-interactive authentication (RFC 4256). macOS Remote Login and most
   PAM servers offer `publickey,keyboard-interactive` and no `password`.
   - SSHMessages: USERAUTH_INFO_REQUEST (60, parsed when PK_OK parsing fails) and
     USERAUTH_INFO_RESPONSE (61); request method `keyboard-interactive`.
   - Offer `.keyboardInteractive(password:)`: hidden prompts get the password, visible
     ones "". After 2 prompt rounds it answers "" so a wrong password fails fast.
   - Available-methods bit `.keyboardInteractive`.
   - Server side: parses the method and always rejects it (unchanged behaviour).

2026-11-02 (security review): keyboard-interactive answers only the first hidden prompt whose text
contains "password" or "passphrase" in each round; every other prompt (2FA codes, "other password")
gets an empty reply, so a hostile server can't collect the password twice or under another label.
