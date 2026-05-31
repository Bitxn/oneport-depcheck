GITHUB_ACTIONS_TEMPLATE = """\
name: Dependency Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 9 * * 1'  # Every Monday 9am UTC

jobs:
  depcheck:
    name: oneport-depcheck
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Install oneport-depcheck
        run: pip install oneport-depcheck

      - name: Run vulnerability scan
        run: |
          depcheck scan -r requirements.txt --fail-on CRITICAL,HIGH

      - name: Generate SBOM
        run: depcheck sbom -r requirements.txt

      - name: Upload SBOM as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.spdx.json
            sbom.cyclonedx.json
"""

GITLAB_CI_TEMPLATE = """\
depcheck:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pip install oneport-depcheck
    - depcheck scan -r requirements.txt --fail-on CRITICAL,HIGH
    - depcheck sbom -r requirements.txt
  artifacts:
    paths:
      - sbom.spdx.json
      - sbom.cyclonedx.json
    expire_in: 30 days
  only:
    - main
    - merge_requests
"""


def generate_github_actions(output_path: str = ".github/workflows/depcheck.yml") -> str:
    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(GITHUB_ACTIONS_TEMPLATE)
    return output_path


def generate_gitlab_ci(output_path: str = "depcheck-gitlab.yml") -> str:
    with open(output_path, "w") as f:
        f.write(GITLAB_CI_TEMPLATE)
    return output_path