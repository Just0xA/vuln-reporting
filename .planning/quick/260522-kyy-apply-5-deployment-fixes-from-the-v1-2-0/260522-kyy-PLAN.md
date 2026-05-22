---
phase: quick-260522-kyy
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - deploy/vuln-reports.service
  - delivery_config.example.yaml
  - DEPLOYMENT.md
autonomous: true
requirements: [DEPLOY-FIX-1, DEPLOY-FIX-2, DEPLOY-FIX-3, DEPLOY-FIX-4, DEPLOY-FIX-5]

must_haves:
  truths:
    - "deploy/vuln-reports.service no longer logs 'Unknown key name StartLimitIntervalSec in section Service'"
    - "A tracked delivery_config.example.yaml exists at repo root, validates against delivery_config.schema.yaml, and ships in the release tarball"
    - "DEPLOYMENT.md Steps 6 and 7 prefix all symlink commands with sudo -u vuln-reports"
    - "DEPLOYMENT.md Verify section has paste-safe && one-liner variants for both checks"
    - "DEPLOYMENT.md has a step to seed shared/delivery_config.yaml from the example, and the Schema Migration diff references a file that exists"
    - "DEPLOYMENT.md Tenable verify expected-output matches tenable_client.py real output"
  artifacts:
    - path: "delivery_config.example.yaml"
      provides: "Tracked, shippable example config with example.invalid recipients"
      contains: "groups"
    - path: "deploy/vuln-reports.service"
      provides: "StartLimit keys in [Unit] section"
      contains: "StartLimitIntervalSec"
  key_links:
    - from: "DEPLOYMENT.md Schema Migration Note"
      to: "delivery_config.example.yaml"
      via: "diff command reference"
      pattern: "delivery_config.example.yaml"
---

<objective>
Apply 5 deployment fixes found during the v1.2.0 clean-machine deployment walkthrough on a Rocky 9 VM. Four are DEPLOYMENT.md documentation fixes; one is a systemd unit-file fix. A new tracked example config file is also created so the deploy flow seeds a valid delivery_config.yaml and the Schema Migration diff reference resolves.

Purpose: A non-author operator following DEPLOYMENT.md verbatim on a clean machine must succeed without hitting permission errors, paste-collapse failures, a dangling config symlink, or mismatched expected-output text; and the systemd restart rate-limit must actually be enforced.

Output: One code/config commit (systemd unit + example file) and one docs commit (DEPLOYMENT.md edits). NO release tag — release is a separate explicit step the user triggers afterward.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@CLAUDE.md
@deploy/vuln-reports.service
@delivery_config.schema.yaml
@DEPLOYMENT.md
@.gitignore
@.gitattributes

<interfaces>
<!-- Confirmed against source — executor uses these directly, no exploration needed. -->

tenable_client.py real output (replaces the stale "[INFO] Tenable connection verified." expected text in Fix #4):
- Logger (tenable_client.py:112): "Successfully authenticated to Tenable at <url>"
- Print (tenable_client.py:143): "Connection successful. Client is ready."

deploy/vuln-reports.service current state:
- [Unit] section: lines 29-32 (Description, After, Wants)
- [Service] section: StartLimitIntervalSec=300 (line 80) and StartLimitBurst=5 (line 81) are MISPLACED here; Restart=on-failure (78) and RestartSec=30 (79) correctly stay.

DEPLOYMENT.md anchors:
- Step 6 "Symlink shared paths": lines 142-154, six `ln -sfn` commands, currently NO sudo prefix.
- Step 7 "Point current at the new release": lines 156-160, one `ln -sfn ... current` command, currently NO sudo prefix.
- Verify section: dry-run multi-line block lines 226-231; connectivity multi-line block lines 238-243; stale expected text line 245.
- Configure Credentials section: lines 168-218 (handles .env only).
- Schema Migration Note diff: lines 543-546 references current/delivery_config.example.yaml.

delivery_config.schema.yaml requirements for a valid example (draft-07):
- Root: object with required `groups` (array, minItems 0), additionalProperties false.
- Each group requires: name, schedule, reports, email. additionalProperties false.
- schedule: requires frequency (weekly|monthly|on_demand); weekly also requires day_of_week + time (HH:MM); time pattern "^([01][0-9]|2[0-3]):[0-5][0-9]$".
- reports: array minItems 1, enum from the slug list (use executive_kpi, trend_analysis, etc.).
- filters: optional; {} allowed; if tag_category present, tag_value required (and vice versa).
- email: requires subject (minLength 1) + recipients (array minItems 1, format email). cc/reply_to optional, format email.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Fix systemd unit (#5) and create tracked example config (#3a)</name>
  <files>deploy/vuln-reports.service, delivery_config.example.yaml</files>
  <action>
Fix #5 — Move the StartLimit keys to the correct section. In deploy/vuln-reports.service, DELETE the two lines `StartLimitIntervalSec=300` and `StartLimitBurst=5` from the `[Service]` section (currently lines 80-81, under the "Restart policy" comment block). Leave `Restart=on-failure` and `RestartSec=30` where they are in `[Service]`. ADD `StartLimitIntervalSec=300` and `StartLimitBurst=5` to the `[Unit]` section (after `Wants=network-online.target`, line 32). Per systemd.unit(5) these keys belong in `[Unit]`; placing them in `[Service]` causes systemd to log "Unknown key name 'StartLimitIntervalSec' in section 'Service', ignoring." and silently drops the restart-storm rate limit. Match the file's existing comment style — a brief comment in `[Unit]` noting these bound the Restart= rate limit is appropriate but keep it surgical; do not restructure the section-header comment banners.

Fix #3a — Create the new tracked file `delivery_config.example.yaml` at repo ROOT. Model it on the CLAUDE.md delivery_config example and make it VALID against delivery_config.schema.yaml. Include one or two example groups demonstrating the common shape (a weekly group with a tag filter and a reports list). Use ONLY example.invalid recipients (e.g. ciso@example.invalid, security-team@example.invalid) and placeholder values per constraint D-04-08 — no real data. Add a top-of-file comment explaining this is a template to be copied to shared/delivery_config.yaml and edited. Use report slugs from the schema enum (executive_kpi, trend_analysis). Keep the schedule weekly with day_of_week + time (HH:MM 24h) so it satisfies the conditional required fields. Do NOT add fields the schema forbids (additionalProperties is false at the group, schedule, filters, and email levels).

Verify the file is NOT excluded from the repo or tarball: it is not matched by any .gitignore pattern (only `delivery_config.yaml` is ignored, not `delivery_config.example.yaml`), and it is NOT export-ignored in .gitattributes (no root-level example pattern exists there). No edits to .gitignore or .gitattributes are needed — just confirm via the verify commands below.
  </action>
  <verify>
    <automated>python -c "import yaml,jsonschema,sys; cfg=yaml.safe_load(open('delivery_config.example.yaml')); sch=yaml.safe_load(open('delivery_config.schema.yaml')); jsonschema.validate(cfg, sch); print('SCHEMA OK')"</automated>
    <automated>git check-ignore delivery_config.example.yaml; if [ $? -eq 0 ]; then echo "FAIL: ignored"; exit 1; else echo "NOT IGNORED OK"; fi</automated>
    <automated>git -c core.quotepath=off archive HEAD 2>/dev/null | tar -tzf - 2>/dev/null | grep -q delivery_config.example.yaml && echo "IN TARBALL OK" || echo "NOTE: not committed yet — confirm after commit via git add + re-archive"</automated>
    <automated>grep -v '^#' deploy/vuln-reports.service | grep -A6 '^\[Unit\]' | grep -c 'StartLimit'</automated>
  </verify>
  <done>StartLimitIntervalSec and StartLimitBurst appear in [Unit] (count 2) and are absent from [Service]; Restart=on-failure and RestartSec=30 remain in [Service]; delivery_config.example.yaml exists at repo root, validates against the schema, is not gitignored, uses only example.invalid recipients, and is not export-ignored.</done>
</task>

<task type="auto">
  <name>Task 2: Apply DEPLOYMENT.md doc fixes (#1, #2, #3b, #4)</name>
  <files>DEPLOYMENT.md</files>
  <action>
Surgical edits only — match existing DEPLOYMENT.md style. Do not rewrite sections wholesale.

Fix #1 — Step 6 "Symlink shared paths" (lines 144-154) and Step 7 (lines 158-160): prefix every `ln -sfn` command with `sudo -u vuln-reports` (matching Steps 4-5 which already use that prefix). That is all six Step 6 symlink lines plus the single Step 7 `current` symlink line. The release dir and /opt/vuln-reporting are owned by vuln-reports (750), so an operator account hits "Permission denied" without the prefix. Keep the inline comments and grouping in Step 6 intact.

Fix #2 — Verify section: add a paste-safe `&&` one-liner variant for BOTH checks. For the dry-run check (lines 226-231) add: `sudo -u vuln-reports bash -c "cd /opt/vuln-reporting/current && .venv/bin/python run_all.py --dry-run"`. For the connectivity check (lines 238-243) add: `sudo -u vuln-reports bash -c "cd /opt/vuln-reporting/current && .venv/bin/python tenable_client.py"`. The one-liner MUST be present (the multi-line `cd<newline>...` form collapses to one line on paste and `cd` gets "too many arguments"). Whether you keep the multi-line form alongside or replace it is your call — recommend replacing with the one-liner to remove the footgun, with a one-sentence note that it is paste-safe.

Fix #3b — Add a step to seed shared/delivery_config.yaml. There is currently NO step that creates it (Step 6 symlinks it; Configure Credentials only handles .env), so the symlink dangles and run_all.py validates 0 groups. Add a delivery-config seeding block in or right after the "Configure Credentials" section, mirroring the .env copy pattern: `sudo -u vuln-reports cp /opt/vuln-reporting/current/delivery_config.example.yaml /opt/vuln-reporting/shared/delivery_config.yaml` followed by an edit step (`sudo -u vuln-reports nano /opt/vuln-reporting/shared/delivery_config.yaml`). Note that, like .env, this lives in shared/ (operator-managed, survives upgrades) and is symlinked into each release by Step 6. Keep the prose tight and consistent with the existing Configure Credentials voice.

Fix #4 — Verify Tenable connectivity expected output (line 245): replace `Expected: [INFO] Tenable connection verified.` with the REAL output from tenable_client.py: the log line "Successfully authenticated to Tenable at <url>" and the stdout print "Connection successful. Client is ready." Present both so the operator knows what success looks like.

Note on Fix #3 part (b)/Schema Migration: the diff reference at lines 543-546 (`current/delivery_config.example.yaml`) now resolves because Task 1 created that tracked file — no edit to the Schema Migration Note is strictly required, but confirm the path matches the new filename exactly (`delivery_config.example.yaml`). If it does, leave it; if it differs, correct it.
  </action>
  <verify>
    <automated>grep -c 'sudo -u vuln-reports ln -sfn' DEPLOYMENT.md</automated>
    <automated>grep -c 'cd /opt/vuln-reporting/current && .venv/bin/python' DEPLOYMENT.md</automated>
    <automated>grep -c 'cp /opt/vuln-reporting/current/delivery_config.example.yaml /opt/vuln-reporting/shared/delivery_config.yaml' DEPLOYMENT.md</automated>
    <automated>grep -q 'Connection successful. Client is ready.' DEPLOYMENT.md && grep -q 'Successfully authenticated to Tenable' DEPLOYMENT.md && echo "EXPECTED-OUTPUT OK"</automated>
    <automated>grep -c 'Tenable connection verified' DEPLOYMENT.md</automated>
  </verify>
  <done>Step 6 has 7 `sudo -u vuln-reports ln -sfn` lines (six Step 6 + one Step 7); both Verify checks have the paste-safe && one-liner; a delivery_config.yaml seeding cp step exists; the connectivity expected-output shows the real tenable_client.py strings and the stale "Tenable connection verified" text is gone (count 0); the Schema Migration diff path matches delivery_config.example.yaml.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| operator → server filesystem | Operator copy-pastes documented commands as root / via sudo -u vuln-reports |
| repo → release tarball | git archive HEAD strips export-ignored paths; new example file must ship |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-kyy-01 | Information Disclosure | delivery_config.example.yaml | mitigate | Use only example.invalid placeholder recipients (D-04-08); no real asset/recipient data committed |
| T-kyy-02 | Tampering | DEPLOYMENT.md command edits | mitigate | Surgical edits matching existing style; verify gates assert exact command strings present |
| T-kyy-03 | Denial of Service | systemd restart rate limit | mitigate | Restore StartLimitIntervalSec/StartLimitBurst in [Unit] so restart-storm protection is enforced |
| T-kyy-SC | Tampering | npm/pip/cargo installs | accept | No package installs in this plan; jsonschema/yaml are existing dev deps |
</threat_model>

<verification>
- Schema validation of delivery_config.example.yaml passes against delivery_config.schema.yaml.
- New example file is tracked (not gitignored) and ships in `git archive HEAD` after commit.
- systemd unit: StartLimit keys live in [Unit], not [Service]; no other keys moved.
- DEPLOYMENT.md: all sudo prefixes, both paste-safe one-liners, the config seeding step, and corrected expected-output present; stale text removed.
- Two clean commits: code/config (Task 1), docs (Task 2). No v1.2.1 tag created.
</verification>

<success_criteria>
- All 5 fixes applied exactly as specified, surgically.
- delivery_config.example.yaml is valid, tracked, shippable, placeholder-only.
- An operator following DEPLOYMENT.md verbatim on a clean Rocky 9 machine completes Steps 6-8, Configure Credentials, and Verify without permission errors, paste-collapse, dangling config, or mismatched expected output.
- No release tagged or published.
</success_criteria>

<output>
Create `.planning/quick/260522-kyy-apply-5-deployment-fixes-from-the-v1-2-0/260522-kyy-SUMMARY.md` when done.
</output>
