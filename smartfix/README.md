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
- An LLM. The workflow defaults to the Contrast-hosted LLM, so no extra key is required.

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

`GITHUB_TOKEN` is provided automatically. If you switch off the Contrast LLM, add your
LLM key as a secret too (e.g. `ANTHROPIC_API_KEY`).

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
commit it to the default branch. The workflow sets up **JDK 23 (Temurin)** before the
SmartFix step, because WebGoat v2025.3 builds with Java 23 and the SmartFix action does
not install Java itself. Without that step the initial build fails immediately. The
`build_command` is `./mvnw -B -ntp clean test`. WebGoat's test run is slow; if a specific
unit test is flaky in CI you can fall back to `./mvnw -B -ntp clean package -DskipTests`
to get unblocked (SmartFix still compiles its fix, it just won't run tests).

## Step 5 — run it and review

Trigger it from the Actions tab (workflow_dispatch) or wait for the daily schedule. It
will open PRs on branches named `smartfix/remediation-...`, one per fix, up to
`max_open_prs`. Review and test each PR, then merge. On merge, the workflow's PR-close
path notifies Contrast. Always review and test SmartFix PRs before merging.

For the demo, a clean arc is: show the Critical SQLi findings in Contrast, trigger
SmartFix, open the generated PR and walk the diff plus the security test it adds, merge,
and show Contrast acknowledging the remediation.

## LLM options

The workflow uses `use_contrast_llm: 'true'` (Contrast-hosted model), the simplest path.
To bring your own, set `use_contrast_llm: 'false'` and supply one of: an Anthropic key
with `agent_model: 'anthropic/claude-sonnet-4-5-20250929'`, AWS Bedrock credentials, or
Azure OpenAI. See the action inputs at
https://github.com/Contrast-Security-OSS/contrast-ai-smartfix-action/blob/main/action.yml.

## Important notes

- Legal: using SmartFix submits your code and findings to the configured LLM under that
  LLM's terms. Confirm this is acceptable for the repo you point it at.
- This is an AI integration that opens PRs and sends code to an LLM. Get IT/security
  approval before enabling it on anything beyond a throwaway WebGoat fork.
- Supported severities are Critical and High; CSRF is currently excluded.
- SmartFix is a Contrast product and its inputs/behavior change. Verify against the
  current docs (https://docs.contrastsecurity.com/en/set-up-contrast-ai-smartfix.html)
  and the action repo before relying on this.
