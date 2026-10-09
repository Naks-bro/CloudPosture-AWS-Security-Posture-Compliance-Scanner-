# Run everything offline (no AWS account, no cloud) - Claude Code prompt

Offline here means: **no AWS credentials, no AWS calls.** Tests and the demo use `moto` (a fake AWS in memory) and
the bundled `sample_data/`. Network is needed only once, to `pip install` the dependencies.
(Fully air-gapped install: on a connected machine run `pip download -r requirements-dev.txt -d wheelhouse`,
copy `wheelhouse/` over, then `pip install --no-index --find-links wheelhouse -r requirements-dev.txt`.)

## Paste this into `claude` from the repo root

```text
Set up and run CloudPosture fully OFFLINE on this machine. Do not use or request any AWS credentials, do not call
real AWS, and do not run `aws configure`/`aws login`. Everything must work with moto and the bundled sample data.
Read CLAUDE.md first. Work step by step, run each command, and fix any failure before moving on.

1. Environment
   - Check `python --version` (need 3.10+). Create and activate `.venv`
     (Windows: `.venv\Scripts\activate`).
   - `pip install -r requirements-dev.txt && pip install -e .`
   - Safety: to guarantee nothing can reach AWS, set dummy credentials for this session only:
     AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_DEFAULT_REGION=us-east-1
     AWS_EC2_METADATA_DISABLED=true, and make sure AWS_PROFILE is unset.

2. Verify the code offline
   - `python -m pytest -q` -> expect all 74 tests to pass. Report the count; if anything fails, diagnose and fix it.
   - `python scripts/generate_docs.py --check` -> must exit 0.
   - `python -m cloudposture list-checks` -> expect 26 checks.
   - `python -m cloudposture demo` -> prints the sample scan summary.
   - `python -m cloudposture demo --output-dir reports` -> writes CSV + JSON; confirm the CSV has 64 data rows
     and 15 columns.

3. Exercise the scanner offline against a fake AWS account
   - Run `python scripts/generate_sample_data.py` (builds a simulated insecure account in moto, runs the REAL
     scanner on it, rewrites sample_data/). Then confirm `git diff --stat sample_data` shows only timestamp/ID noise
     or nothing, and that `python -m cloudposture demo` still works.
   - Prove the read-only guard: write a throwaway script (outside the repo, or delete it afterwards) that,
     inside `moto.mock_aws()`, creates an `AwsClients(ScanConfig())` and calls `iam.create_user`; it must raise
     `ReadOnlyViolation`. Report the result.

4. Run the dashboard offline
   - `streamlit run dashboard/app.py --server.port 8501` (run in background).
   - Confirm `curl -s http://localhost:8501/_stcore/health` returns `ok`.
   - Using Playwright (pip install playwright; use an already-installed Chromium, do not download anything
     if offline) or by describing what you see, verify in Demo Data mode: header shows DEMO DATA + READ-ONLY SCAN,
     Overview shows score 48% and 31 PASS / 33 FAIL / 0 ERROR / 0 N/A, the Findings tab filters work and clicking a
     row opens the detail panel, Compliance labels ISO/PCI/SOC 2 as "Approximate / thematic mapping",
     Reports tab downloads a 64-row CSV and a JSON file, and uploading that JSON in the sidebar (Upload) works.
   - Take screenshots into the scratchpad / a temp folder, not into docs/.

5. Optional: offline "live" path
   - Start a local fake AWS: `moto_server -p 5555` (background), then with AWS_ENDPOINT_URL=http://127.0.0.1:5555
     (and the dummy credentials above) populate it using `tests/aws_env.py::build_demo_account()` and run
     `python -m cloudposture scan --regions us-east-1`. Expect ~26 checks and, because the local endpoint cannot
     resolve S3 Control's account-prefixed host, a single ERROR on S3-001 (that is an artifact of the local
     endpoint, not a bug). Stop moto_server afterwards.

6. Report
   - A table: step, command, result (pass/fail), notes. List anything that needed network access.
   - Finish by telling me the exact commands to start the dashboard again, and how to stop it.
   - Do not commit or push anything unless I ask.
```

## Plain commands (if you don't want to use Claude)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e .
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_DEFAULT_REGION=us-east-1
python -m pytest -q
python -m cloudposture demo
streamlit run dashboard/app.py          # http://localhost:8501 -> Demo Data
```

Stop the dashboard with `Ctrl+C`. Leaving the dummy `testing` credentials set guarantees no real AWS call is possible.
