#!/bin/bash
# Config Protection Hook (PreToolUse: Edit|Write)
# Blocks agents from weakening linter/formatter configs
# Exit 2 = block, Exit 0 = allow

# Allow override for intentional config changes
[ "${ECC_ALLOW_CONFIG_EDIT:-0}" = "1" ] && exit 0

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

case "$(basename "$FILE_PATH")" in
  .eslintrc|.eslintrc.js|.eslintrc.json|.eslintrc.cjs|.eslintrc.mjs|eslint.config.js|eslint.config.mjs|eslint.config.ts)
    echo "BLOCKED: Cannot modify ESLint config. Fix the code instead." >&2
    exit 2
    ;;
  biome.json|biome.jsonc)
    echo "BLOCKED: Cannot modify Biome config. Fix the code instead." >&2
    exit 2
    ;;
  .prettierrc|.prettierrc.json|prettier.config.js|prettier.config.mjs|prettier.config.cjs)
    echo "BLOCKED: Cannot modify Prettier config. Fix the code instead." >&2
    exit 2
    ;;
  .ruff.toml|ruff.toml|pyproject.toml)
    echo "BLOCKED: Cannot modify Ruff/Python config. Fix the code instead." >&2
    exit 2
    ;;
  tsconfig.json|tsconfig.*.json)
    NEW_CONTENT=$(echo "$INPUT" | jq -r '(.tool_input.new_string // "") + (.tool_input.content // "")')
    if echo "$NEW_CONTENT" | grep -qE '"strict"\s*:\s*false|"noImplicitAny"\s*:\s*false|"skipLibCheck"\s*:\s*true'; then
      echo "BLOCKED: Cannot relax TypeScript strict settings. Fix the type errors instead." >&2
      exit 2
    fi
    ;;
  .stylelintrc|.stylelintrc.json|stylelint.config.js)
    echo "BLOCKED: Cannot modify Stylelint config. Fix the code instead." >&2
    exit 2
    ;;
  .editorconfig)
    echo "BLOCKED: Cannot modify EditorConfig. Fix the code instead." >&2
    exit 2
    ;;
esac
