# agent-eval/

This directory holds the setup that lets a coding-agent CLI run the analysers as a tool. So far it covers the Antigravity CLI (`agy`), checked by one smoke test. The harness itself (agents, prompts, scoring) does not exist yet.

```bash
make analyzers-image          # the tool runs this image
AGY=/path/to/agy agent-eval/smoke_agy.sh
```

The smoke test was run with agy 1.5.10 on Windows 11 (Git Bash, Docker Desktop) and passed. agy ran the tool, read `esbmc.log` and answered `12`, using 28 222 tokens. No `--model` is passed, so agy uses the model in the user's `settings.json`. agy's JSON output does not name the model, so every run has to record it separately.

## How agy is restricted

- `--mode accept-edits` allows file edits. A command runs only if it matches an allow rule, and any other command is denied without a prompt. That holds even when the user's own agy preset auto-approves commands. In the default `auto` mode, an unlisted `git log` and a file write both went through in testing.
- `--mode plan` denied the allowed command as well, so the harness cannot use it.
- `agy-settings.json` is passed with `--settings`. It is applied to that session only and never saved.
- An allow rule matches the whole command line. `command(git rev-parse --short HEAD)` matched that command. `command(git rev-parse)`, `command(git rev-parse *)` and `command(git rev-parse:*)` did not match it, and only `command(*)` matched everything.
- A denied command ends the turn: `response` comes back empty and `denied_actions` lists the command.

That is why every tool takes no arguments and works on fixed names in its working directory: `target.c`, an optional `compile` file, and `analyzers-out/`. For each program, the harness will create a fresh workspace with those files and a copy of `tools/`, and set `C_SECURE_BUILD` so the copied tool can find `analyzers/run.sh`.

## Tools

- `tools/run_analyzers.sh` runs `analyzers/run.sh` in the image on `./target.c` and prints each tool's exit code. The allow rule is `command(bash tools/run_analyzers.sh)`.

## Open points

- agy loads the user's global `~/.gemini/config/GEMINI.md` into every session, and that file imports personal agent rules. Those rules would end up in the harness prompt. A custom agent with `excludeDefaultComponents: true` may drop them, but this has not been tested yet.
- Claude Code needs the same setup: `claude -p` with `--allowedTools "Bash(bash tools/run_analyzers.sh)"`, plus a way to skip the user's `CLAUDE.md`. Not done yet.
