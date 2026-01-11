#!/usr/bin/env bash
set -e

# Usage: ./init.sh <app-name>
# Example: ./init.sh my-app

APP_NAME=$1

# Validation
if [ -z "$APP_NAME" ]; then
  echo "❌ Error: App name missing."
  echo "Usage: $0 <app-name>" 
  echo "Example: $0 my-app"
  exit 1
fi

# Error handling
trap 'echo "❌ Error on line $LINENO"; exit 1' ERR

echo "🚀 Initializing project: $APP_NAME"

# 1. Create Next.js app
# --turbopack: enabled
# --yes: accept defaults (handles React Compiler prompts)
bun create next-app "$APP_NAME" \
  --typescript \
  --tailwind \
  --app \
  --src-dir \
  --import-alias "@/*" \
  --no-eslint \
  --no-git \
  --turbopack \
  --yes

cd "$APP_NAME"

# 2. Git Init (Required for Lefthook)
git init
echo "node_modules" >> .gitignore
echo ".DS_Store" >> .gitignore

# 3. Setup Bun & Biome
echo "📦 Installing Biome & Lefthook..."
bun add -D @biomejs/biome lefthook

# Generate Biome Config
bun biome init --jsonc

# 4. Setup Lefthook
echo "🪝 Setting up Lefthook..."
cat > lefthook.yml <<EOF
pre-commit:
  parallel: true
  commands:
    biome:
      glob: "*.{js,ts,cjs,mjs,d.cts,d.mts,jsx,tsx,json,jsonc}"
      run: bunx biome check --write --css-parse-tailwind-directives=true --no-errors-on-unmatched --files-ignore-unknown=true {staged_files} && git update-index --again
EOF

# Install hooks
bunx lefthook install

# 5. Setup shadcn/ui (Non-interactive)
echo "🎨 Setting up shadcn/ui..."

# Install dependencies manually to prevent potential package manager detection issues
bun add tailwind-merge clsx class-variance-authority lucide-react

# Run init using FLAGS instead of a pre-existing file.
# This prevents the "components.json already exists" error.
bunx shadcn@latest init --base-color neutral --css-variables --yes

# 6. Final Clean
echo "🧹 Running initial format..."
bunx biome check --write --css-parse-tailwind-directives=true  .

# 7. Initial Commit
git add .
git commit -m "feat: init project $APP_NAME"

echo "✅ Project $APP_NAME ready."
echo "Run: cd $APP_NAME && bun dev"