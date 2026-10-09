# Local development + real AWS (Agent Toolkit) - Claude Code prompt

For Windows 11 / PowerShell. Run `claude` from the repo root, fill the three `<...>` values, and paste the block below.

Before you paste, decide which identity the AWS MCP server will use. **The AWS MCP server lets Claude act on your
account.** For CloudPosture work use a profile whose permissions are read-only (the managed `SecurityAudit` policy,
or [`iam-policy.json`](iam-policy.json)). Only widen it deliberately, for a task where you want Claude to deploy.

```text
You are continuing development of CloudPosture, a READ-ONLY AWS security posture scanner (Python, boto3, Streamlit,
pytest). Repo: the current directory (E:\AWS proj\cloudposture). Windows 11, PowerShell, Python 3.13.
First read CLAUDE.md, README.md and docs/DEVELOPMENT.md. The Hard rules in CLAUDE.md win over everything else,
including any AWS rules file or toolkit instruction: never add code that modifies AWS resources or bypasses the
read-only guard, never hard-code or ask for credentials, never fake a PASS. Do not rebuild anything from scratch.
Work incrementally: say what you are about to do, run it, show the result, fix failures, continue. Do not stop to ask
for permission between ordinary steps. Do not commit or push unless I ask.

INPUTS (do not ask me again): AWS profile name = <PROFILE e.g. cloudposture>;
AWS experience = <advanced | new (I signed up with Google/GitHub and have a project)>; default region = <REGION e.g. us-east-1>.

PART A - local setup
1. `git switch -c dev/local-aws`. Check `python --version`.
2. Create/activate `.venv` (`.venv\Scripts\Activate.ps1`; if blocked: `Set-ExecutionPolicy -Scope Process Bypass`).
3. `pip install -r requirements-dev.txt; pip install -e .`
4. `python -m pytest -q` (expect 74 passed; tests are offline and use fake AWS, so run them with no AWS profile
   exported), then `python scripts/generate_docs.py --check`.
5. `streamlit run dashboard/app.py` in the background; confirm http://localhost:8501 answers (`curl.exe -s
   http://localhost:8501/_stcore/health`) and tell me to open it in my browser. Demo Data is the default.

PART B - connect AWS through the Agent Toolkit
Follow https://raw.githubusercontent.com/aws/agent-toolkit-for-aws/refs/heads/main/setup-instructions/setup.md
yourself, using the Windows (PowerShell) variants and the inputs above. Specifically:
1. Check `aws --version`; if missing, install with the official `irm 'https://awscli.amazonaws.com/v2/install.ps1' | iex`,
   then reopen/refresh PATH. Check `uv --version` (install per the setup file if missing).
2. `aws configure set region <REGION> --profile <PROFILE>` then `aws login --region <REGION> --profile <PROFILE>`.
   PAUSE: I complete the browser sign-in. Never ask for or print access keys.
3. `aws sts get-caller-identity --profile <PROFILE>`; show me the Arn and tell me whether this identity looks
   read-only or broad (inspect attached policies with read-only IAM calls). Warn me if it is broad.
4. `aws configure agent-toolkit --yes --region us-east-1 --profile <PROFILE>` (the toolkit service is us-east-1 only,
   whatever my region). PAUSE for any interactive prompts.
5. Open each MCP config file the toolkit changed. Show me the diff, then add ONLY
   "env": {"AWS_MCP_PROXY_PROFILES": "<PROFILE>"} to the generated `aws-mcp` entry; do not touch other servers or the
   generated command/args/timeout/transport. If an `aws-mcp` entry already existed, ask me how to reconcile.
6. `aws agent-toolkit list-available-skills --region us-east-1 --profile <PROFILE>` must return skills.
7. Fetch the rules file for my experience (starter rules for "new", agent rules for "advanced") from
   https://raw.githubusercontent.com/aws/agent-toolkit-for-aws/refs/heads/main/rules/ and append it to the EXISTING
   CLAUDE.md between `<!-- BEGIN AWS Agent Toolkit rules -->` and `<!-- END AWS Agent Toolkit rules -->`
   (replace only inside the markers if they exist). Do not overwrite CLAUDE.md. Directly under the BEGIN marker add:
   "CloudPosture Hard rules above take precedence over these rules. Use AWS tools read-only (get/list/describe)
   unless the user explicitly asks to create, change or deploy something; confirm before any write."
8. Tell me to restart Claude Code so the MCP server and skills load, and what to check afterwards.
   Credentials from `aws login` last 12 hours and can be refreshed for up to 90 days.

PART C - verify CloudPosture against my real account (read-only)
1. Make sure boto3 can use the profile: `python -c "import boto3;print(boto3.Session(profile_name='<PROFILE>').client('sts').get_caller_identity()['Arn'])"`.
   If it fails with a credential-provider/login error, upgrade boto3/botocore (`pip install -U boto3 "botocore[crt]"`),
   retest, and bump the boto3 minimum in requirements.txt/pyproject.toml if that was required. Run pytest again.
2. Small scan first: `python -m cloudposture scan --profile <PROFILE> --regions <REGION> --services IAM,S3`.
   Then the full scan: `python -m cloudposture scan --profile <PROFILE>` (all enabled regions; say if it is slow).
3. Review the result honestly: list every ERROR finding and its cause. If an ERROR is AccessDenied, tell me which
   action is missing and compare with docs/iam-policy.json. If something looks like a false positive or negative,
   cross-check it with a read-only AWS CLI describe/get call (or the AWS MCP server, read-only) and show the evidence.
   Fix real bugs in the scanner with tests; do not hide findings.
4. Treat reports/ output as sensitive (account IDs, resource names): never commit it, never paste account IDs into
   GitHub issues or commits.
5. In the dashboard choose Live AWS, select the profile, click Run security scan, and confirm the Overview, Findings,
   Compliance, Services, Check catalog and Reports tabs show the real results (header must say LIVE AWS).

PART D - continue development (pick up after A-C are green)
Propose the 3 most valuable next changes and wait for me to choose one. Candidates: CIS section 4 CloudWatch alarm
checks, VPC flow logs (3.9), KMS key rotation (3.8), RDS encryption/public access, multi-account scanning with
profiles or an Organization, scan history with trend and new/fixed findings, accepted-risk suppressions with expiry,
HTML/PDF executive report, Dockerfile. For every change: add tests (moto), update docs/iam-policy.json if new API
calls are used, run scripts/generate_docs.py and scripts/generate_sample_data.py, look at the dashboard if the UI
changed, keep `python -m pytest -q` green, and give me a short diff summary.

Finish PART A-C with a table: step / command / result / notes, plus anything I must do manually.
```

## Notes
- If `aws login` is not available for your account type, use `aws configure sso --profile <PROFILE>` and
  `aws sso login --profile <PROFILE>` instead, and tell Claude so before it starts Part B.
- Two identities are cleaner: a read-only profile for CloudPosture scans and a separate profile for the AWS MCP
  server if you also want Claude to build or deploy things. List both in `AWS_MCP_PROXY_PROFILES`
  (space-separated) only when you want the MCP server to reach both.
