#!/bin/sh
# Start (or restart) the test sshd on 127.0.0.1:2222, then run the integration tests:
#   scripts/test-sshd.sh && VSHELL_SSHD=1 swift test --package-path Packages/VShellCore
set -e
dir=$(cd "$(dirname "$0")" && pwd)
docker build -q -t vshell-test-sshd "$dir/test-sshd" >/dev/null
docker rm -f vshell-test-sshd >/dev/null 2>&1 || true
docker run -d --name vshell-test-sshd -p 127.0.0.1:2222:22 vshell-test-sshd >/dev/null
# Second server like macOS: keyboard-interactive only, on 2223.
docker build -q -t vshell-test-sshd-kbd "$dir/test-sshd-kbd" >/dev/null
docker rm -f vshell-test-sshd-kbd >/dev/null 2>&1 || true
docker run -d --name vshell-test-sshd-kbd -p 127.0.0.1:2223:22 vshell-test-sshd-kbd >/dev/null
sleep 1
echo "test sshd up on 127.0.0.1:2222 (password) and :2223 (keyboard-interactive only), vshell / vshell-test"
