# Development & Claude Code quick start

## 1. Pull and run locally

```bash
git clone https://github.com/Naks-bro/CloudPosture-AWS-Security-Posture-Compliance-Scanner-.git
cd CloudPosture-AWS-Security-Posture-Compliance-Scanner-
git checkout claude/cloudposture-aws-scanner-k26t6l      # or main, once merged

python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt && pip install -e .

python -m pytest -q                                      # 74 tests, offline
streamlit run dashboard/app.py                           # opens http://localhost:8501 (Demo Data)
```

## 2. Connect your AWS account (read-only)

Do this on your own machine - `aws login` opens a browser.

1. Install the AWS CLI v2, then sign in with SSO or the browser flow:
   `aws configure sso --profile cloudposture-readonly` then `aws sso login --profile cloudposture-readonly`
   (or `aws login --profile cloudposture-readonly` if you use the new login flow).
2. Attach [`iam-policy.json`](iam-policy.json) (or the managed `SecurityAudit` policy) to that identity.
3. `aws sts get-caller-identity --profile cloudposture-readonly` should succeed.
4. Scan: `python -m cloudposture scan --profile cloudposture-readonly`, or in the dashboard pick **Live AWS**,
   select the profile and click **Run security scan**.

Start with a non-production account and review the results.

## 3. Set up the Agent Toolkit for AWS (optional, for AWS-aware Claude Code)

From the repo root, start Claude Code (`claude`) and paste:

> Set up Agent Toolkit for AWS by following the instructions at
> https://raw.githubusercontent.com/aws/agent-toolkit-for-aws/refs/heads/main/setup-instructions/setup.md
> Use profile name `cloudposture-readonly` and region `<your region>`. I will complete the browser sign-in myself.
> Append any rules to the existing CLAUDE.md between marker comments - do not overwrite it.

Claude installs the CLI, runs `aws configure agent-toolkit --yes --region us-east-1 --profile <profile>`
(the toolkit service is us-east-1 only) and adds `AWS_MCP_PROXY_PROFILES=<profile>` to the generated `aws-mcp`
entry. Review what it changes before accepting. Restart `claude` afterwards.

## 4. Starter prompt for Claude Code (development)

Paste this at the start of a session in the repo root:

```text
You are working on CloudPosture, a READ-ONLY AWS security posture scanner (Python, boto3, Streamlit, pytest).
First read CLAUDE.md, README.md and docs/CHECKS.md, then run `python -m pytest -q` to confirm a green baseline.

Rules: never add code that modifies AWS resources or bypasses the read-only guard; never request or hard-code
credentials; never fake a PASS (use ERROR / N/A); do not invent ISO/PCI/SOC 2 mappings (they stay "approximate");
keep UI free of scoring logic.

Work incrementally: explain the plan briefly, implement, run the tests, show me the diff summary, then continue.
If you change checks or mappings, also run scripts/generate_docs.py and scripts/generate_sample_data.py.
If you change the dashboard, run it and verify it visually before saying it is done.

Today's task: <describe the change here>
```

### Good first tasks to hand Claude
- **More checks:** CIS section 4 monitoring alarms (CloudWatch metric filters), VPC flow logs (3.9), KMS key rotation (3.8), RDS encryption/public access.
- **Multi-account:** scan several profiles / an AWS Organization and aggregate results.
- **History:** save scans and show posture trend and new/fixed findings between two scans.
- **Exports:** PDF/HTML executive report; SARIF or JSON-lines for ingestion.
- **Packaging:** Dockerfile, `pip` release, GitHub Pages demo from `sample_data/`.
- **Hardening:** suppressions file (accepted risks) with expiry and justification.

## 5. Making changes safely
- Branch per change; keep `python -m pytest -q` green (CI also runs `scripts/generate_docs.py --check`).
- Adding a check: see the checklist in [`CLAUDE.md`](../CLAUDE.md).
- Never commit `.env`, `reports/` output or real account data. Screenshots must use demo data only.
