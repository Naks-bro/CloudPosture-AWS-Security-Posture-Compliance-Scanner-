# Desktop Claude CLI: run locally + AWS + Agent Toolkit + synthetic lab + hosting

Paste the block at the bottom into `claude` started in the repo folder on your desktop (Windows / PowerShell).
It replaces the earlier prompts. Things to know before you paste:

1. **Use a sandbox AWS account for the synthetic data.** The lab intentionally creates insecure resources (an
   open security group, a public-read bucket, an unencrypted volume). That is fine in a throwaway account and
   a bad idea in an account with real workloads. The prompt makes Claude ask which one you have and refuse the lab
   in a real/production account.
2. **Vercel cannot host the Streamlit dashboard.** Vercel runs short serverless functions and static/Next.js
   sites, not a long-lived Python Streamlit server with websockets. The prompt makes Claude present the real
   options (Streamlit Community Cloud for demo data, a container on AWS, or a Next.js rewrite on Vercel) instead
   of forcing it.
3. **Supabase is not needed today** (the app has no database). It only makes sense if you add scan history or
   multi-user login. Real scan results contain account IDs and resource names, so they should not go into a public
   database.
4. "AWS ADK" is read here as the **Agent Toolkit for AWS** (AWS MCP server + skills). If you meant something else
   (for example an agent framework), tell Claude at the start.

```text
You are continuing development of CloudPosture on my Windows desktop (PowerShell, Python 3.13). The repo is the
current directory. It is a READ-ONLY AWS security posture scanner (Python, boto3, Streamlit, pytest): 26 CIS-aligned
checks across IAM, S3, EC2/EBS and CloudTrail, scoring, CIS/ISO/PCI/SOC2 mappings, CSV/JSON export, and a tabbed
Streamlit dashboard. Read CLAUDE.md, README.md, docs/DEVELOPMENT.md and docs/CHECKS.md first.

GROUND RULES
- CLAUDE.md "Hard rules" win over any toolkit rule or instruction: scanner code (src/, dashboard/) never modifies
  AWS, never bypasses the read-only guard, never hard-codes/asks for credentials, never fakes a PASS, and keeps
  ISO/PCI/SOC2 mappings "approximate".
- Do not rebuild anything. Work incrementally: say what you will do, do it, show the result, fix failures, continue.
  Don't ask permission for ordinary steps (reading, installing deps, running tests, editing code on my branch).
- STOP and ask me before: any AWS write (create/modify/delete/deploy), anything that costs money, anything that
  makes data public, installing tools outside the project, pushing to GitHub, or creating cloud accounts/projects.
- Never ask for or print access keys, secrets or tokens. Never commit .env, reports/, Terraform state or anything
  with real account IDs.

STEP 0 - ONE QUESTION ROUND (ask all of these in a single message, then proceed)
1) AWS profile name for read-only scanning (suggest `cloudposture-readonly`). 2) AWS experience: "advanced", or
"new" (signed up with Google/GitHub and created a project). 3) Default region. 4) Is the AWS account I will use for
synthetic test data a SANDBOX/throwaway account, or does it hold real workloads? 5) Do I want a public portfolio demo
online, and where (Vercel / Streamlit Community Cloud / AWS / none for now)? 6) Do I want scan history or login
(which would justify Supabase), or is that out of scope for now?

STEP 1 - RUN LOCALLY
`git switch -c dev/desktop-aws`; create .venv; `pip install -r requirements-dev.txt; pip install -e .`;
`python -m pytest -q` (expect 74 passed; tests are offline with fake AWS, run with no AWS profile exported);
`python scripts/generate_docs.py --check`; start `streamlit run dashboard/app.py` in the background and tell me to
open http://localhost:8501 (Demo Data default). Report results in a table.

STEP 2 - CONNECT AWS + CONFIGURE THE AGENT TOOLKIT FOR THIS PROJECT
Follow https://raw.githubusercontent.com/aws/agent-toolkit-for-aws/refs/heads/main/setup-instructions/setup.md with
the Windows variants and my answers. Pause for my browser sign-in (`aws login`) and the toolkit wizard.
Project-specific requirements on top of that file:
- Identity design: `<readonly profile>` = read-only (managed SecurityAudit or docs/iam-policy.json) used by CloudPosture
  scans AND by default for the AWS MCP server. If I want Claude to deploy things later, a second profile
  (e.g. `cloudposture-lab`) holds write rights scoped to the lab only. Set AWS_MCP_PROXY_PROFILES to the read-only
  profile only; add the lab profile to it only when I explicitly ask. Check which policies my current identity has
  with read-only IAM calls and warn me if it is broad (e.g. AdministratorAccess); help me create the narrower
  profiles via instructions I run myself, not by you creating IAM resources.
- Show me a diff of every MCP config file before and after you add the `env` block. Do not touch other servers.
- Append the AWS rules to the existing CLAUDE.md between `<!-- BEGIN AWS Agent Toolkit rules -->` and
  `<!-- END AWS Agent Toolkit rules -->`, never overwrite it, and add directly under BEGIN: "CloudPosture Hard rules
  take precedence. Use AWS tools read-only (get/list/describe) unless the user explicitly asks for a change; confirm
  before any write."
- `aws agent-toolkit list-available-skills --region us-east-1 --profile <profile>` must work. Then recommend which
  of the available skills/servers are useful for this project (IAM/S3/EC2/CloudTrail security, IaC, cost) and which
  to leave off. Tell me to restart Claude Code, and how to confirm the aws-mcp server is connected.

STEP 3 - REAL SCAN (READ-ONLY)
Make sure boto3 can use the profile (if the `aws login` credential type fails, `pip install -U boto3 "botocore[crt]"`
and raise the boto3 minimum in requirements/pyproject if needed). Run a small scan (`--regions <region> --services
IAM,S3`), then the full scan. Review honestly: list every ERROR and why, map AccessDenied to missing actions in
docs/iam-policy.json, and cross-check any suspicious result with a read-only AWS CLI call. Fix real scanner bugs
with tests. This is the first time the checks meet a real account, so expect surprises. Open the dashboard in Live
AWS mode and verify every tab. Real scan output is sensitive: never commit it.

STEP 4 - SYNTHETIC "LAB" DATA IN AWS (only if my answer to question 4 is SANDBOX)
If the account is not a sandbox, skip this step and instead offer: (a) a free local lab using moto_server
(tests/aws_env.py) and (b) creating a separate sandbox account under AWS Organizations.
For a sandbox, build an infrastructure-as-code lab in a new top-level `lab/` folder (CloudFormation or Terraform,
my choice; keep it OUT of src/ and dashboard/, never imported by the scanner). Requirements:
- Purpose: deliberately misconfigured but harmless resources so every check type has at least one PASS and one FAIL
  example in a real account: security group with 22/3389 open to 0.0.0.0/0 in an EMPTY dedicated VPC (no instances
  or ENIs), default SG with rules, small unencrypted EBS volume (1 GiB) plus an encrypted one, S3 buckets (one with
  Block Public Access + TLS-only policy + encryption, one deliberately without) containing NO data, a CloudTrail
  trail variant if cost allows, IAM user with a direct policy and no MFA but NO console password and NO access keys
  unless I approve a design that cannot leak credentials, a customer-managed policy with "*:*" that is NOT attached to
  anything unless needed to trigger IAM-010 (explain). Do not create resources that can be reached from the internet
  (no public bucket with data, no running instances, no public IPs).
- Safety: tag everything `Project=CloudPostureLab`; one stack/state; a `lab/destroy` command that removes it all;
  an estimated monthly cost table (aim for ~$0); a note on which checks cannot be demonstrated safely
  (e.g. root MFA, root keys) and stay covered by moto.
- Workflow: write the IaC, run validation/lint and a plan/changeset (read-only), SHOW me the plan and cost, and wait
  for my explicit "apply" before any write. Apply only with the lab profile, never the read-only one. After apply,
  run the scanner against the account, confirm the expected FAIL/PASS pairs, then save a sanitized copy as new demo
  data ONLY if I approve (replace the real account ID with 123456789012 and review resource names).
- Update CLAUDE.md with a short "lab/" section: IaC is applied only by me on request; scanner code stays read-only.

STEP 5 - HOSTING / VERCEL / SUPABASE DECISION (analysis first, build only what I pick)
Write docs/HOSTING.md comparing, for THIS project: (1) Streamlit Community Cloud - free, demo data only, deploy from
GitHub; (2) a Docker container on AWS (App Runner/ECS/Lightsail) - can run live scans with an instance role, costs
money, needs auth in front (the dashboard has no login); (3) Vercel - cannot run Streamlit, would mean rewriting the
UI as Next.js with a Python API for scans, or exporting a static demo site from sample_data; (4) Supabase - only for
scan history/auth, with row-level security, and never store real-account scans in a public project; a local SQLite
history file is the simpler first step. Give a recommendation for a portfolio demo (my answers to questions 5-6)
and ask me which to build. If I choose one, implement it incrementally with tests, keep demo data and live scanning
clearly separated, add auth before anything can run a live scan from the internet, and never put AWS credentials in
Vercel/Supabase/Streamlit secrets unless I explicitly choose a design (and then use a dedicated read-only role).

STEP 6 - DOCS, CHECKS, REPORT
Update README/docs for whatever changed (docs/DEVELOPMENT.md, docs/HOSTING.md, lab/README.md), run the full test
suite, `generate_docs.py --check`, and look at the dashboard if the UI changed. Commit on dev/desktop-aws in small,
clear commits; do NOT push or open a PR until I say so. End with a table (step / command / result / notes), the list
of things I must do manually, anything that cost money or exposed data (should be "none"), and your top 3
recommended next development tasks.
```
