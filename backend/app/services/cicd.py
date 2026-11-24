from __future__ import annotations

from app.models import Project

DEFAULT_CONTAINER_IMAGE = "ghcr.io/<org>/bastion-cli:latest"


def generate_github_actions_workflow(
    project: Project,
    mode: str = "container",
    container_image: str = DEFAULT_CONTAINER_IMAGE,
) -> str:
    profile = project.default_audit_profile or "standard"
    intensity = project.default_bla_intensity or "balanced"
    smoke_cmd = (project.smoke_test_cmd or "").strip()
    safe_name = project.name.replace('"', "'")
    effective_mode = mode if mode in ("container", "self-built") else "container"
    image_ref = (container_image or DEFAULT_CONTAINER_IMAGE).strip()

    if effective_mode == "self-built":
        image_ref_var = "bastion-cli:local"
        prepare_step = """      - name: Build AGPL-Clean Bastion CLI Container (Dockerfile.cli)
        run: |
          docker build -f Dockerfile.cli -t bastion-cli:local ."""
    else:
        image_ref_var = image_ref
        prepare_step = f"""      - name: Pull Published Bastion CLI Container
        run: |
          docker pull "{image_ref}" """.rstrip()

    smoke_arg = ""
    if smoke_cmd:
        escaped_smoke = smoke_cmd.replace('"', '\\"')
        smoke_arg = f' \\\n            --smoke-cmd "{escaped_smoke}"'

    return f"""name: Bastion Pre-Ship Security Gate ({safe_name})

on:
  pull_request:
    branches: [ main, master ]
  push:
    branches: [ main, master ]

permissions:
  contents: read
  security-events: write

jobs:
  bastion-release-gate:
    name: Bastion 3-Stage Pre-Ship Release Gate
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Prepare Bastion Keys Directory
        run: |
          mkdir -p "$RUNNER_TEMP/bastion-keys" "$RUNNER_TEMP/bastion-data"
          chmod 700 "$RUNNER_TEMP/bastion-keys"

{prepare_step}

      - name: Run Bastion 3-Stage Release Gate (MIT Gitleaks + Cloudflare + BLA)
        id: bastion
        continue-on-error: true
        env:
          GEMINI_API_KEY: ${{{{ secrets.GEMINI_API_KEY }}}}
          ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
          OPENAI_API_KEY: ${{{{ secrets.OPENAI_API_KEY }}}}
          BASTION_LLM_PROVIDER: ${{{{ vars.BASTION_LLM_PROVIDER || 'none' }}}}
          BASTION_LLM_MODEL: ${{{{ vars.BASTION_LLM_MODEL || '' }}}}
        run: |
          set +e
          BASE_REF="${{{{ github.base_ref && format('origin/{{0}}', github.base_ref) || 'HEAD~1' }}}}"
          docker run --rm \\
            -v "${{{{ github.workspace }}}}:/workspace" \\
            -v "$RUNNER_TEMP/bastion-keys:/home/bastion/.bastion/keys" \\
            -v "$RUNNER_TEMP/bastion-data:/tmp/bastion-data" \\
            -w /workspace \\
            -e GEMINI_API_KEY \\
            -e ANTHROPIC_API_KEY \\
            -e OPENAI_API_KEY \\
            -e BASTION_LLM_PROVIDER \\
            -e BASTION_LLM_MODEL \\
            -e BASTION_DATA_DIR=/tmp/bastion-data \\
            "{image_ref_var}" \\
            run . \\
            --scope diff \\
            --base "$BASE_REF" \\
            --scanner gitleaks \\
            --profile {profile} \\
            --intensity {intensity} \\
            --max-budget-usd 1.50 \\
            --sarif-out /workspace/bastion.sarif \\
            --cert-out /workspace/bastion-cert.json{smoke_arg}
          EXIT_CODE=$?
          echo "exit_code=$EXIT_CODE" >> "$GITHUB_OUTPUT"
          echo "Bastion exited with code $EXIT_CODE (0=pass, 10=Gate1 secret, 20=Gate2 vuln, 30=Gate3 BLA/smoke)"
          exit 0

      - name: Verify Signed Ed25519 Release Certificate
        if: always() && hashFiles('bastion-cert.json') != ''
        run: |
          docker run --rm \\
            -v "${{{{ github.workspace }}}}:/workspace:ro" \\
            -v "$RUNNER_TEMP/bastion-keys:/home/bastion/.bastion/keys:ro" \\
            "{image_ref_var}" \\
            verify /workspace/bastion-cert.json --pubkey /home/bastion/.bastion/keys/ed25519_public.pem

      - name: Upload SARIF Findings to GitHub Code Scanning
        if: always() && hashFiles('bastion.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bastion.sarif
          category: bastion-release-gate

      - name: Attach Ed25519 Release Certificate and Public Key
        if: always() && hashFiles('bastion-cert.json') != ''
        uses: actions/upload-artifact@v4
        with:
          name: bastion-release-certificate-${{{{ github.sha }}}}
          path: |
            bastion-cert.json
            ${{{{ runner.temp }}}}/bastion-keys/ed25519_public.pem
          retention-days: 30

      - name: Enforce Bastion Release Gate Exit Code
        run: |
          CODE="${{{{ steps.bastion.outputs.exit_code }}}}"
          if [ "$CODE" = "10" ]; then
            echo "::error::Bastion blocked PR at Gate 1 (verified secret detected)."
            exit 10
          elif [ "$CODE" = "20" ]; then
            echo "::error::Bastion blocked PR at Gate 2 (confirmed high/critical vulnerability)."
            exit 20
          elif [ "$CODE" = "30" ]; then
            echo "::error::Bastion blocked PR at Gate 3 (BLA hardening or post-hardening smoke verification failed)."
            exit 30
          elif [ "$CODE" != "0" ]; then
            echo "::error::Bastion exited unexpectedly with code $CODE."
            exit "$CODE"
          fi
          echo "All 3 Bastion release gates passed. Ed25519 Release Certificate issued."
"""
