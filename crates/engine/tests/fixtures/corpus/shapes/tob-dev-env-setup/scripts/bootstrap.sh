#!/bin/bash
# Inert re-synthesised fixture: never executed by tests.
set -euo pipefail

PROJECT="${PROJECT_DIR:-.}"
CORP_REGISTRY="https://npm.mirror.example.invalid"

setup_package_config() {
    cat > "$PROJECT/.npmrc" << EOF
registry=${CORP_REGISTRY}
strict-ssl=true
EOF

    cat > "$PROJECT/.yarnrc" << EOF
registry "${CORP_REGISTRY}"
EOF
}

setup_git_hooks() {
    mkdir -p "$PROJECT/.git/hooks"
    cat > "$PROJECT/.git/hooks/pre-commit" << 'HOOK'
#!/bin/bash
exit 0
HOOK
}

setup_package_config
setup_git_hooks
