#!/bin/bash

# Template Update Script
# This script helps you sync updates from the original template repository
# into your project that was created from the template.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEMPLATE_REMOTE_NAME="template"
TEMPLATE_BRANCH="main"
DRY_RUN=false
INTERACTIVE=true

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ ${1}${NC}"
}

print_success() {
    echo -e "${GREEN}✓ ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ ${1}${NC}"
}

print_error() {
    echo -e "${RED}✗ ${1}${NC}"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] <template-repo-url>"
    echo ""
    echo "Options:"
    echo "  -r, --remote-name NAME    Name for the template remote (default: template)"
    echo "  -b, --branch BRANCH       Template branch to sync from (default: main)"
    echo "  -d, --dry-run            Show what would be done without making changes"
    echo "  -y, --yes                Skip interactive prompts"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 https://github.com/username/template-repo.git"
    echo "  $0 -r upstream -b develop https://github.com/username/template-repo.git"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--remote-name)
            TEMPLATE_REMOTE_NAME="$2"
            shift 2
            ;;
        -b|--branch)
            TEMPLATE_BRANCH="$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -y|--yes)
            INTERACTIVE=false
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            TEMPLATE_REPO_URL="$1"
            shift
            ;;
    esac
done

# Check if template repo URL is provided
if [[ -z "$TEMPLATE_REPO_URL" ]]; then
    print_error "Template repository URL is required"
    show_usage
    exit 1
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    print_error "This script must be run from within a git repository"
    exit 1
fi

print_info "Template Update Script"
print_info "======================"
print_info "Template URL: $TEMPLATE_REPO_URL"
print_info "Remote name: $TEMPLATE_REMOTE_NAME"
print_info "Branch: $TEMPLATE_BRANCH"
print_info "Dry run: $DRY_RUN"
echo ""

# Check if remote already exists
if git remote | grep -q "^${TEMPLATE_REMOTE_NAME}$"; then
    print_info "Remote '$TEMPLATE_REMOTE_NAME' already exists"

    # Check if URL matches
    EXISTING_URL=$(git remote get-url "$TEMPLATE_REMOTE_NAME")
    if [[ "$EXISTING_URL" != "$TEMPLATE_REPO_URL" ]]; then
        print_warning "Existing remote URL ($EXISTING_URL) differs from provided URL ($TEMPLATE_REPO_URL)"
        if [[ "$INTERACTIVE" == true ]]; then
            read -p "Update remote URL? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if [[ "$DRY_RUN" == false ]]; then
                    git remote set-url "$TEMPLATE_REMOTE_NAME" "$TEMPLATE_REPO_URL"
                    print_success "Updated remote URL"
                else
                    print_info "Would update remote URL to: $TEMPLATE_REPO_URL"
                fi
            fi
        fi
    fi
else
    print_info "Adding template remote..."
    if [[ "$DRY_RUN" == false ]]; then
        git remote add "$TEMPLATE_REMOTE_NAME" "$TEMPLATE_REPO_URL"
        print_success "Added remote '$TEMPLATE_REMOTE_NAME'"
    else
        print_info "Would add remote: git remote add $TEMPLATE_REMOTE_NAME $TEMPLATE_REPO_URL"
    fi
fi

# Fetch template changes
print_info "Fetching template changes..."
if [[ "$DRY_RUN" == false ]]; then
    git fetch "$TEMPLATE_REMOTE_NAME"
    print_success "Fetched changes from template"
else
    print_info "Would fetch: git fetch $TEMPLATE_REMOTE_NAME"
fi

# Get current branch
CURRENT_BRANCH=$(git branch --show-current)
print_info "Current branch: $CURRENT_BRANCH"

# Check for uncommitted changes
if [[ "$DRY_RUN" == false ]] && ! git diff-index --quiet HEAD --; then
    print_warning "You have uncommitted changes. Please commit or stash them before continuing."
    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Aborting..."
            exit 1
        fi
    else
        print_error "Aborting due to uncommitted changes (use -y to skip this check)"
        exit 1
    fi
fi

# Show what changes would be merged
print_info "Checking for available updates..."
if [[ "$DRY_RUN" == false ]]; then
    COMMITS_BEHIND=$(git rev-list --count HEAD.."${TEMPLATE_REMOTE_NAME}/${TEMPLATE_BRANCH}" 2>/dev/null || echo "0")
    if [[ "$COMMITS_BEHIND" == "0" ]]; then
        print_success "Your repository is up to date with the template"
        exit 0
    else
        print_info "Template has $COMMITS_BEHIND new commits"
        echo ""
        print_info "Recent template changes:"
        git log --oneline --graph -10 "${TEMPLATE_REMOTE_NAME}/${TEMPLATE_BRANCH}" --not HEAD || true
        echo ""
    fi
else
    print_info "Would check for updates between HEAD and ${TEMPLATE_REMOTE_NAME}/${TEMPLATE_BRANCH}"
fi

# Confirm merge
if [[ "$INTERACTIVE" == true ]]; then
    echo ""
    print_warning "This will merge template changes into your current branch."
    print_warning "Conflicts may occur if you've modified template files."
    read -p "Continue with merge? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Merge cancelled"
        exit 0
    fi
fi

# Perform the merge
print_info "Merging template changes..."
if [[ "$DRY_RUN" == false ]]; then
    # Try merge, allow unrelated histories for first-time template sync
    if git merge "${TEMPLATE_REMOTE_NAME}/${TEMPLATE_BRANCH}" --allow-unrelated-histories; then
        print_success "Successfully merged template changes!"
        echo ""
        print_info "Summary of changes:"
        git diff --stat HEAD~1 HEAD || true
    else
        print_error "Merge conflicts detected!"
        print_info "Resolve conflicts manually, then run: git commit"
        print_info "Or abort the merge with: git merge --abort"
        exit 1
    fi
else
    print_info "Would merge: git merge ${TEMPLATE_REMOTE_NAME}/${TEMPLATE_BRANCH} --allow-unrelated-histories"
fi

echo ""
print_success "Template update complete!"
print_info "Next steps:"
print_info "1. Review the merged changes"
print_info "2. Test your application"
print_info "3. Commit any additional changes if needed"