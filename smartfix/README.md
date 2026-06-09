# Contrast AI SmartFix for the WebGoat demo

SmartFix reads your Critical/High Contrast Assess findings, generates code fixes with an
LLM, and opens pull requests against your repository. It then verifies each fix by
running your build, and notifies Contrast when a PR is merged or closed.

## Where this runs (read first)

SmartFix edits application **source code**, so it runs in a **fork of the WebGoat source
repo** (https://github.com/WebGoat/WebGoat), not in this Kubernetes deploy repo. This
repo deploys a prebuilt WebGoat image and has no Java to build or fix. The Contrast
findings reference WebGoat source files and line numbers, which exist in that fork, so
SmartFix can locate and patch them.

The running container (this repo) and the source fork are linked only by the Contrast
application: the same app whose findings your `demo/run-exercises.mjs` run produced.

## Prerequisites

- Contrast Assess enabled on the app, with Critical/High findings present. Run
  `demo/run-exercises.mjs` against the deployed WebGoat first so findings exist.
- The app is Java (supported). SmartFix supports Java, .NET Core/Framework, Node.js, Python.
- A GitHub fork of WebGoat that uses GitHub Actions.
- A Contrast API-only service user (below).
- An LLM. This workflow uses **Google Gemini (free tier)** by default; get a key at
  https://aistudio.google.com/apikey. You can swap to your own Anthropic/Bedrock/Azure
  key, or the Contrast-hosted LLM if your org is entitled (see LLM options below).

## Step 1 — create a Contrast API-only user

In the Contrast UI: Organization settings > Users > Add User. Give it the **Edit**
organization role and **View** or **Edit** application access, then check **API only**.
Hosted and on-prem differ slightly; follow the hosted steps if you're on a hosted
instance. After creating it, hover the "API only" label to copy the user's **Service
key**.

Build that user's Authorization header:

```bash
echo -n 'apionly-user@yourorg.com:THEIR_SERVICE_KEY' | base64
```

That base64 value is `CONTRAST_AUTHORIZATION_KEY`. The `CONTRAST_API_KEY` is your
organization API key (Contrast UI > User settings > API).

## Step 2 — gather the five values

- `CONTRAST_HOST` — your instance host including protocol, e.g. `https://eval.contrastsecurity.com`
- `CONTRAST_ORG_ID` — organization UUID (User settings > API)
- `CONTRAST_APP_ID` — the application UUID. Open the app in Contrast; it's the value
  after `applications/` in the URL. This must be the WebGoat app your agent reports.
- `CONTRAST_AUTHORIZATION_KEY` — from Step 1
- `CONTRAST_API_KEY` — organization API key

## Step 3 — set GitHub variables and secrets (on the WebGoat fork)

Repository > Settings > Secrets and variables > Actions.

Variables (not secret):
- `CONTRAST_HOST`
- `CONTRAST_ORG_ID`
- `CONTRAST_APP_ID`

Secrets:
- `CONTRAST_AUTHORIZATION_KEY`
- `CONTRAST_API_KEY`
- `GEMINI_API_KEY` (the workflow's default LLM; or the key for whichever LLM you choose)

`GITHUB_TOKEN` is provided automatically. Paste each secret directly into the GitHub
field, do not pipe through your clipboard, since the `base64` tool appends a newline and a
trailing `\n` in the Authorization header breaks Contrast API auth.

## Step 3.5 — validate the credentials locally (recommended)

Before wiring anything into GitHub, confirm the five values actually work. Put them in
your local `.env` and run:

```bash
node scripts/smartfix-preflight.mjs
```

It authenticates against the Contrast API, confirms the app id resolves to the WebGoat
app, and reports the Critical/High finding counts SmartFix will act on. It never prints
secret values. Fix anything it flags before continuing.

## Step 4 — add the workflow

Copy `smartfix.yml` from this folder into the fork at `.github/workflows/smartfix.yml`,
commit it to the default branch. Key things the workflow already handles, learned the
hard way:

- **JDK setup.** The SmartFix action installs Python and Node but not Java, so the
  workflow adds a `setup-java` step. The version MUST match the WebGoat version your fork
  is on: **23** for a branch off the `v2025.3` tag (matches the image this repo deploys),
  **25** for `main` (WebGoat 2026.x). Wrong JDK = "release version NN not supported".
- **Build command** is `./mvnw -B -ntp clean package -Dmaven.test.skip=true` — compiles
  the app without compiling/running tests, which gives a reliable green baseline (SmartFix
  requires the build to pass before it generates fixes). `debug_mode: true` is on so the
  real Maven output shows if a build fails.

Tip: base the fork on the `v2025.3` tag so the source matches the running app, then use
JDK 23.

## Step 5 — run it and review

Trigger it from the Actions tab (workflow_dispatch) or wait for the daily schedule. It
opens PRs on branches named `smartfix/remediation-...`, one per fix, up to `max_open_prs`
(set to 2 here to stay within the Gemini free tier). Review and test each PR, then merge.
On merge, the workflow's PR-close path notifies Contrast. Always review and test SmartFix
PRs before merging. Also enable Settings > Actions > General > "Allow GitHub Actions to
create and approve pull requests", or the run can't open PRs.

For the demo, a clean arc is: show the Critical SQLi findings in Contrast, trigger
SmartFix, open the generated PR and walk the diff, merge, and show Contrast acknowledging
the remediation. (The workflow sets `skip_writing_security_test: true` to conserve free-
tier LLM calls; drop that if you want SmartFix to add a security test per fix.)

## LLM options

The workflow defaults to **Google Gemini, free tier** (`use_contrast_llm: 'false'`,
`agent_model: 'gemini/gemini-2.5-flash'`, key in `GEMINI_API_KEY`). Notes:

- The free tier allows roughly **20 flash requests/day**, and SmartFix uses several per
  fix, so a run produces a couple of PRs then hits the quota. That's why `max_open_prs` is
  2 and `skip_writing_security_test` is true. Space runs across days, or enable billing.
- **gemini-2.5-pro is NOT on the free tier** (limit 0) — use flash, or a paid key for pro.
- To bring your own: set the relevant key and `agent_model` for Anthropic
  (`anthropic/claude-haiku-4-5-20251001` is cheap; sonnet for better fixes), AWS Bedrock,
  or Azure, or `use_contrast_llm: 'true'` if your org is entitled to the Contrast LLM. See
  https://github.com/Contrast-Security-OSS/contrast-ai-smartfix-action/blob/main/action.yml.

Validate creds first with `node scripts/smartfix-preflight.mjs` (Step 3.5).

## Important notes

- Legal: using SmartFix submits your code and findings to the configured LLM under that
  LLM's terms. Confirm this is acceptable for the repo you point it at.
- This is an AI integration that opens PRs and sends code to an LLM. Get IT/security
  approval before enabling it on anything beyond a throwaway WebGoat fork.
- Supported severities are Critical and High; CSRF is currently excluded.
- SmartFix is a Contrast product and its inputs/behavior change. Verify against the
  current docs (https://docs.contrastsecurity.com/en/set-up-contrast-ai-smartfix.html)
  and the action repo before relying on this.
