# St. Cecilia Grant Tracker

A password-protected dashboard that finds grant and funding opportunities for
St. Cecilia School (Broussard, LA), tracks their deadlines, and lets staff mark each one
**Apply** or **Decline**.

- **Every other Monday (about 6 AM Central)** a GitHub Action checks:
  - **Grants.gov:** federal grants that nonprofits can apply for.
  - **13 watched funder pages:** Stuller, Community Foundation of Acadiana, GOHSEP and the
    LA Center for Safe Schools, LA Division of the Arts, Raskob Foundation, Toshiba America
    Foundation, KaBOOM!, Dollar General Literacy, Laura Bush Foundation, Whole Foods Market
    Foundation, and Hancock Whitney. Edit `scanner/sources.json` to add more.
  - **Claude AI web search across 8 areas:** Acadiana funders, Louisiana corporate giving,
    Louisiana state programs, Catholic funders, STEM, literacy/music/arts,
    facilities/safety/playgrounds, and teacher grants. All 8 areas are searched every scan.
  - Deadline countdowns on the dashboard still update daily. They're calculated in the browser.
  - To scan at any other time, use Actions → Grant scan → **Run workflow** (manual runs always go ahead).
- **PreK–8 focus:** for every opportunity the AI records:
  - the grade levels it serves
  - a 1–5 fit score for a private Catholic PreK–8 school
  - **why we're a good candidate** and **why we might not be**

  Anything scoring below 3 is dropped. This removes high-school-only, college, research,
  and public-school-only programs. Change `min_fit_score` in `sources.json` to be stricter
  or looser.
- **Dashboard:**
  - Scroll the list and click an item to see what it funds, who can apply, why it fits,
    and its deadline.
  - Choose **Apply** or **Decline** to move it to the *Applying* or *Declined* tab. Both tabs
    can be searched.
  - Applying items have a stage (Preparing → Submitted → Awarded / Not awarded) and notes.
  - Deadlines can be added to a calendar.
- **Privacy:** all data is encrypted with the shared password before it goes into the
  repository. The public website and repo only hold scrambled files. Without the password
  you see only a login box.

## How it works

```
GitHub Action (every 2 wks) ──► scanner/scan.py ──► docs/data/grants.enc.json (encrypted)
                                                    │
Browser ── password ──► docs/index.html decrypts ◄──┘
   │
   └─ Apply / Decline ──► GitHub API ──► docs/data/decisions.enc.json (encrypted)
```

## One-time setup (about 15 minutes)

### 1. Create the repository
Create a **public** repository on GitHub (free GitHub Pages requires public). The data is
encrypted, so public is safe. Push this folder to it.

### 2. Create a token so the dashboard can save decisions
GitHub → your picture → **Settings → Developer settings → Personal access tokens →
Fine-grained tokens → Generate new token**
- Repository access: **Only select repositories** → this repo
- Permissions → Repository permissions → **Contents: Read and write** (nothing else)
- Expiration: up to you (1 year is fine; set a reminder to renew)

Copy the token (starts with `github_pat_`).

### 3. Get an Anthropic API key (for the AI search)
At https://console.anthropic.com → API Keys → Create key. Add a few dollars of credit and
set a monthly spend limit under Billing. Make sure **web search** is enabled for the
organization (Console → Settings → Privacy / web search).

### 4. Add the secrets
Repo → **Settings → Secrets and variables → Actions → New repository secret**:

| Name | Value |
|---|---|
| `DASHBOARD_PASSWORD` | The shared password staff will type (use 12+ characters, e.g. a short phrase) |
| `GH_DATA_TOKEN` | The token from step 2 |
| `ANTHROPIC_API_KEY` | The key from step 3 (leave out to run without AI) |

### 5. Turn on GitHub Pages
Repo → **Settings → Pages → Build and deployment → Source: GitHub Actions**.

### 6. Run the first scan
Repo → **Actions → Grant scan → Run workflow**. When it finishes (2–5 minutes),
the dashboard is at `https://<your-username>.github.io/<repo-name>/`.

Share that link and the password with the people who should have access.

## Day-to-day

- **Changing who has access:** change the password. Add a secret `OLD_DASHBOARD_PASSWORD`
  with the old one, update `DASHBOARD_PASSWORD`, run the workflow once, then delete
  `OLD_DASHBOARD_PASSWORD`. Existing decisions are kept and re-encrypted.
- **Adding funders to watch:** add `{"funder": "...", "url": "..."}` to `watch_pages`
  in `scanner/sources.json`.
- **Updating the school profile** (grades, priorities): edit `school_profile` in
  `scanner/sources.json`. The AI uses it to judge fit.
- **Banner photo (optional):** save a school photo you have permission to use as
  `docs/assets/hero.jpg`. It appears behind the headline with a navy tint. Without it,
  the banner shows navy with music-note artwork.
- **Team notes:** every opportunity has "Why we're a good candidate" and "Why we might not
  be" boxes. They're shared with everyone and can be saved before deciding to apply.
- **Scan problems** appear at the bottom of the dashboard under *Scan status*, and
  in the repo's **Actions** tab.

## Cost

- GitHub: free.
- Claude API: estimated **$3–5/month**, roughly $1.50–2.50 per scan, with about 2 scans a month.
  - The web search uses Claude Sonnet 5.5: all 8 search areas every other week, up to 6
    searches each.
  - Reading funder pages and screening federal grants uses Claude Haiku 5.5, which costs
    pennies.
  - Check the first scan's real cost in the Anthropic Console and set a monthly spend limit
    there (e.g. $8).

  Settings in `scanner/sources.json` → `"ai"`:

  | Want | Change | Approx. cost/month |
  |---|---|---|
  | Cheapest | `"model": "claude-haiku-5-5"` | ~$1 |
  | Default | (as shipped: Sonnet, every 2 weeks) | ~$3–5 |
  | Best quality | `"model": "claude-opus-5-5"` | ~$6–10 |
  | Every week | in `.github/workflows/grant-scan.yml`, change `$(( week % 2 )) -eq 0` to `true` | ×2 |
  - To turn AI off entirely, set `"enabled": false`.

## Security notes

- The shared password protects the data. Anyone with the password can read the data and
  save decisions. Pick a strong password and change it when people leave.
- The save token is stored only inside the encrypted data, and it can only edit this one
  repo's files. Someone with the password could technically extract it, so give the token
  only the single permission listed above.
- Commit messages for saved decisions say only "Update decisions". No grant details
  appear in the public history.

## Run locally (optional)

```bash
pip install -r scanner/requirements.txt
DASHBOARD_PASSWORD=test-password-123 python scanner/scan.py --no-ai
python -m http.server 8000 --directory docs   # open http://localhost:8000
```
