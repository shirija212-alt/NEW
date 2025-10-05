# Git Push Instructions

Due to Replit's git protection mechanisms, you need to manually commit and push the changes using the Replit Git pane or Shell.

## Files Added/Modified

### New Files Created:
- `app/` - Complete FastAPI application directory
  - `app/main.py` - FastAPI endpoints
  - `app/analyzers.py` - Hybrid scam detection logic
  - `app/db.py` - Database helpers (credentials now secure)
  - `app/models.py` - Pydantic models
  - `app/train.py` - ML training script
  - `app/scam_model.pkl` - Trained model (< 1 MB)
- `tests/test_phone_analyzer.py` - 13 pytest tests (all passing)
- `test_manual.sh` - Manual API test script
- `GIT_INSTRUCTIONS.md` - This file

### Modified Files:
- `.gitignore` - Added Python and ML model exclusions
- `README.md` - Added FastAPI documentation section

## Method 1: Using Replit Git Pane (Recommended)

1. Open the **Git pane** in Replit:
   - Click "Tools" in the sidebar
   - Select "Git" from the tools list

2. In the Git pane:
   - Review the changed files
   - Stage all files you want to commit
   - Enter commit message: `upgrade: hybrid scam classifier + endpoints + tests`
   - Click "Commit & Push"

3. If prompted for authentication:
   - Use your GitHub username
   - Use a Personal Access Token (not password)
   - Create token at: https://github.com/settings/tokens

## Method 2: Using Shell Commands

Open the Shell and run:

```bash
# Stage all new files
git add app/ tests/ test_manual.sh .gitignore README.md GIT_INSTRUCTIONS.md

# Commit with message
git commit -m "upgrade: hybrid scam classifier + endpoints + tests"

# Update remote URL (if needed)
# Note: Replace with your actual repository URL
git remote set-url origin https://github.com/shirija212-alt/NEW.git

# Push to main branch
git push origin main
```

If you get authentication errors, you may need to use a Personal Access Token:

```bash
# Use this format (replace YOUR_TOKEN and your-username)
git push https://YOUR_TOKEN@github.com/shirija212-alt/NEW.git main
```

## Verify Push

After pushing, verify on GitHub:
- Visit: https://github.com/shirija212-alt/NEW
- Check that the new `app/` directory is visible
- Check the latest commit message

## Security Note

The hard-coded database credentials have been removed from `app/db.py`. The application now requires the DATABASE_URL environment variable, which is securely stored in Replit Secrets.
