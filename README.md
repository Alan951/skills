# Agent Skills

Collection of reusable skills for coding assistants.
This repository is designed primarily for **Claude Code**, but it can also be used with other agents compatible with `SKILL.md`.

## Structure

Each skill lives in its own folder:

- `skills/<skill-name>/SKILL.md`

Example:

- `skills/cvss31`

## Primary Usage with Claude Code

### Option 1: install with `skills` CLI (recommended)

```bash
npx skills add <owner>/<repo> --skill cvss31 -a claude-code
```

### Option 2: copy manually

Copy the skill folder to:

- Project: `.claude/skills/<skill-name>`
- Global: `~/.claude/skills/<skill-name>`

## Compatibility

As long as each skill contains a valid `SKILL.md`, this repository can also be consumed by other agents and tools in the ecosystem.
