# Erlang/OTP

Target version is OTP 28.3. Before running any Erlang/OTP or rebar3 commands, find and activate it:

```sh
. $(kerl list installations | awk '/^otp-28\.3 /{print $2}')/activate
```

# Git workflow

- Commit every conceptual step separately, don't batch unrelated changes
- No sign-off annotations (no `Signed-off-by`, no `Co-Authored-By`, etc.)
- Short commit messages — one line, no body unless truly necessary
- Write messages like a developer would: casual, direct, no AI tone
  - bad: "Refactor the authentication module to improve code maintainability"
  - good: "clean up auth module"
- Never amend commits or rewrite history; use `git revert` in a new commit to undo changes
