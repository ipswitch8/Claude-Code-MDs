@echo off
setlocal enabledelayedexpansion

:: Template Update Script for Windows
:: This script helps you sync updates from the original template repository
:: into your project that was created from the template.

:: Default values
set "TEMPLATE_REMOTE_NAME=template"
set "TEMPLATE_BRANCH=main"
set "DRY_RUN=false"
set "INTERACTIVE=true"
set "TEMPLATE_REPO_URL="

:: Parse command line arguments
:parse_args
if "%~1"=="" goto :args_done
if "%~1"=="-r" (
    set "TEMPLATE_REMOTE_NAME=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="--remote-name" (
    set "TEMPLATE_REMOTE_NAME=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="-b" (
    set "TEMPLATE_BRANCH=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="--branch" (
    set "TEMPLATE_BRANCH=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="-d" (
    set "DRY_RUN=true"
    shift
    goto :parse_args
)
if "%~1"=="--dry-run" (
    set "DRY_RUN=true"
    shift
    goto :parse_args
)
if "%~1"=="-y" (
    set "INTERACTIVE=false"
    shift
    goto :parse_args
)
if "%~1"=="--yes" (
    set "INTERACTIVE=false"
    shift
    goto :parse_args
)
if "%~1"=="-h" goto :show_usage
if "%~1"=="--help" goto :show_usage
if "%~1"=="-?" goto :show_usage
if not "%~1"=="" (
    set "TEMPLATE_REPO_URL=%~1"
    shift
    goto :parse_args
)

:args_done

:: Check if template repo URL is provided
if "%TEMPLATE_REPO_URL%"=="" (
    echo Error: Template repository URL is required
    goto :show_usage
)

:: Check if we're in a git repository
git rev-parse --git-dir >nul 2>&1
if errorlevel 1 (
    echo Error: This script must be run from within a git repository
    exit /b 1
)

echo Template Update Script
echo ======================
echo Template URL: %TEMPLATE_REPO_URL%
echo Remote name: %TEMPLATE_REMOTE_NAME%
echo Branch: %TEMPLATE_BRANCH%
echo Dry run: %DRY_RUN%
echo.

:: Check if remote already exists
git remote | findstr /r "^%TEMPLATE_REMOTE_NAME%$" >nul 2>&1
if not errorlevel 1 (
    echo Info: Remote '%TEMPLATE_REMOTE_NAME%' already exists

    :: Check if URL matches
    for /f "delims=" %%i in ('git remote get-url %TEMPLATE_REMOTE_NAME%') do set "EXISTING_URL=%%i"
    if not "!EXISTING_URL!"=="%TEMPLATE_REPO_URL%" (
        echo Warning: Existing remote URL (!EXISTING_URL!) differs from provided URL (%TEMPLATE_REPO_URL%)
        if "%INTERACTIVE%"=="true" (
            set /p "UPDATE_URL=Update remote URL? (y/N): "
            if /i "!UPDATE_URL!"=="y" (
                if "%DRY_RUN%"=="false" (
                    git remote set-url %TEMPLATE_REMOTE_NAME% %TEMPLATE_REPO_URL%
                    echo Success: Updated remote URL
                ) else (
                    echo Info: Would update remote URL to: %TEMPLATE_REPO_URL%
                )
            )
        )
    )
) else (
    echo Info: Adding template remote...
    if "%DRY_RUN%"=="false" (
        git remote add %TEMPLATE_REMOTE_NAME% %TEMPLATE_REPO_URL%
        echo Success: Added remote '%TEMPLATE_REMOTE_NAME%'
    ) else (
        echo Info: Would add remote: git remote add %TEMPLATE_REMOTE_NAME% %TEMPLATE_REPO_URL%
    )
)

:: Fetch template changes
echo Info: Fetching template changes...
if "%DRY_RUN%"=="false" (
    git fetch %TEMPLATE_REMOTE_NAME%
    echo Success: Fetched changes from template
) else (
    echo Info: Would fetch: git fetch %TEMPLATE_REMOTE_NAME%
)

:: Get current branch
for /f "delims=" %%i in ('git branch --show-current') do set "CURRENT_BRANCH=%%i"
echo Info: Current branch: %CURRENT_BRANCH%

:: Check for uncommitted changes
if "%DRY_RUN%"=="false" (
    git diff-index --quiet HEAD -- >nul 2>&1
    if errorlevel 1 (
        echo Warning: You have uncommitted changes. Please commit or stash them before continuing.
        if "%INTERACTIVE%"=="true" (
            set /p "CONTINUE=Continue anyway? (y/N): "
            if not "!CONTINUE!"=="y" if not "!CONTINUE!"=="Y" (
                echo Info: Aborting...
                exit /b 1
            )
        ) else (
            echo Error: Aborting due to uncommitted changes (use -y to skip this check)
            exit /b 1
        )
    )
)

:: Check for available updates
echo Info: Checking for available updates...
if "%DRY_RUN%"=="false" (
    for /f %%i in ('git rev-list --count HEAD..%TEMPLATE_REMOTE_NAME%/%TEMPLATE_BRANCH% 2^>nul ^|^| echo 0') do set "COMMITS_BEHIND=%%i"
    if "!COMMITS_BEHIND!"=="0" (
        echo Success: Your repository is up to date with the template
        exit /b 0
    ) else (
        echo Info: Template has !COMMITS_BEHIND! new commits
        echo.
        echo Info: Recent template changes:
        git log --oneline --graph -10 %TEMPLATE_REMOTE_NAME%/%TEMPLATE_BRANCH% --not HEAD 2>nul
        echo.
    )
) else (
    echo Info: Would check for updates between HEAD and %TEMPLATE_REMOTE_NAME%/%TEMPLATE_BRANCH%
)

:: Confirm merge
if "%INTERACTIVE%"=="true" (
    echo.
    echo Warning: This will merge template changes into your current branch.
    echo Warning: Conflicts may occur if you've modified template files.
    set /p "MERGE_CONFIRM=Continue with merge? (y/N): "
    if not "!MERGE_CONFIRM!"=="y" if not "!MERGE_CONFIRM!"=="Y" (
        echo Info: Merge cancelled
        exit /b 0
    )
)

:: Perform the merge
echo Info: Merging template changes...
if "%DRY_RUN%"=="false" (
    git merge %TEMPLATE_REMOTE_NAME%/%TEMPLATE_BRANCH% --allow-unrelated-histories
    if not errorlevel 1 (
        echo Success: Successfully merged template changes!
        echo.
        echo Info: Summary of changes:
        git diff --stat HEAD~1 HEAD 2>nul
    ) else (
        echo Error: Merge conflicts detected!
        echo Info: Resolve conflicts manually, then run: git commit
        echo Info: Or abort the merge with: git merge --abort
        exit /b 1
    )
) else (
    echo Info: Would merge: git merge %TEMPLATE_REMOTE_NAME%/%TEMPLATE_BRANCH% --allow-unrelated-histories
)

echo.
echo Success: Template update complete!
echo Info: Next steps:
echo Info: 1. Review the merged changes
echo Info: 2. Test your application
echo Info: 3. Commit any additional changes if needed
exit /b 0

:show_usage
echo Usage: %~n0 [OPTIONS] ^<template-repo-url^>
echo.
echo Options:
echo   -r, --remote-name NAME    Name for the template remote (default: template)
echo   -b, --branch BRANCH       Template branch to sync from (default: main)
echo   -d, --dry-run            Show what would be done without making changes
echo   -y, --yes                Skip interactive prompts
echo   -h, --help               Show this help message
echo.
echo Example:
echo   %~n0 https://github.com/username/template-repo.git
echo   %~n0 -r upstream -b develop https://github.com/username/template-repo.git
exit /b 0