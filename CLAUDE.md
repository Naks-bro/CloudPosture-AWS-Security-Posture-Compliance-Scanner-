# CloudPosture - project guide for Claude Code

Read-only AWS security posture scanner (26 CIS-aligned checks: IAM, S3, EC2/EBS, CloudTrail) with a Streamlit dashboard.

## Hard rules
- **Never add code that creates, modifies, deletes or remediates AWS resources.** Every boto3 client goes through
  `AwsClients` (`src/cloudposture/aws/session.py`), which blocks any operation not named `Get*`/`List*`/`Describe*`
  (plus `GenerateCredentialReport`, `AssumeRole`). Do not weaken or bypass this guard.
- **Never hard-code or ask for AWS credentials.** Use the boto3 credential chain (profile / SSO / env / role).
- **Do not fake results.** If an API cannot give a reliable answer, return `ERROR` or `N/A`, never `PASS`.
- **Do not invent compliance mappings.** CIS may be `exact`; ISO 27001 / PCI DSS / SOC 2 stay `approximate`
  (a test enforces this). Edit only `src/cloudposture/compliance/mappings.py`.
- Never commit `.env`, scan output in `reports/`, or anything containing account IDs.

## Layout
- `src/cloudposture/` - `checks/` (registry + iam/s3/ec2/cloudtrail), `scoring.py`, `reporting.py`, `scanner.py`, `cli.py`
- `dashboard/` - Streamlit UI (`app.py`, `sidebar.py`, `components.py`, `theme.py`, `charts.py`, `data.py`, `views/`).
  UI must not contain scoring logic; add pure functions to `scoring.py` and test them.
- `tests/` - moto-based; `tests/aws_env.py` builds fake accounts. `scripts/` regenerate demo data and docs.

## Commands
```bash
pip install -r requirements-dev.txt && pip install -e .
python -m pytest -q                          # must stay green; offline, no AWS needed
streamlit run dashboard/app.py               # demo data by default
python -m cloudposture scan --profile <p>    # real, read-only scan -> reports/
python scripts/generate_docs.py              # after changing checks or mappings (CI checks this)
python scripts/generate_sample_data.py       # after changing checks (regenerates sample_data/)
```

## Adding a check
1. Decorated function in `src/cloudposture/checks/<service>.py` (`@check(id=..., severity=..., expected=..., remediation=[...])`).
2. Entry in `compliance/mappings.py` (registration fails without it).
3. Add the API actions to `docs/iam-policy.json` (a test verifies coverage).
4. Tests in `tests/test_checks.py`; run `generate_docs.py` and `generate_sample_data.py`.

## UI conventions
Dark security-console look; all dynamic text goes through `html.escape` via `components.py`; use `st.html` for custom HTML.
After UI changes, run the app and look at it (screenshots live in `docs/screenshots/`).
