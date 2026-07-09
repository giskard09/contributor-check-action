#!/usr/bin/env python3
"""Contributor reputation checker for Mycelium/Rama repos.

Screens the author of a new issue/PR for account-shape anomalies and
credential-laundering signals (fabricated DOI/CVE/repo citations) before a
human has to read it by hand. Cluster/coordination detection (cross-repo
actor patterns) is deliberately out of scope for v1 — that stays a manual
judgment call informed by our own actor history, not something derivable
from a single profile snapshot.

Usage:
    python scripts/contributor_check.py --username <handle> --body-file <path> [--json]

Requires: GITHUB_TOKEN env var (or `gh auth token`).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

_TOKEN: str | None = None


def _get_token() -> str:
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            result = subprocess.run(
                ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    if not token:
        print("Error: set GITHUB_TOKEN or `gh auth login`", file=sys.stderr)
        sys.exit(1)
    _TOKEN = token
    return token


def _api(url: str, headers: dict[str, str] | None = None) -> Any:
    """GET a full URL (github.com or elsewhere) and return parsed JSON, or None on 404."""
    req = Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    if url.startswith("https://api.github.com"):
        req.add_header("Authorization", f"Bearer {_get_token()}")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    for attempt in range(3):
        try:
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code in (403, 429) and attempt < 2:
                wait = int(exc.headers.get("Retry-After", "10"))
                wait = min(max(wait, 5), 30)
                print(f"  Rate limited ({exc.code}), waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
        except URLError as exc:
            if attempt < 2:
                time.sleep(3)
                continue
            print(f"  Warning: could not reach {url}: {exc}", file=sys.stderr)
            return None
    return None


def _gh_api(path: str) -> Any:
    return _api(f"https://api.github.com{path}")


# ---------------------------------------------------------------------------
# Signal model
# ---------------------------------------------------------------------------

@dataclass
class Signal:
    name: str
    severity: str  # LOW, MEDIUM, HIGH
    detail: str


@dataclass
class Report:
    username: str
    profile_signals: list[Signal] = field(default_factory=list)
    credential_signals: list[Signal] = field(default_factory=list)

    def _risk(self, signals: list[Signal]) -> str:
        high = sum(1 for s in signals if s.severity == "HIGH")
        medium = sum(1 for s in signals if s.severity == "MEDIUM")
        if high >= 2:
            return "HIGH"
        if high >= 1 or medium >= 3:
            return "MEDIUM"
        return "LOW"

    @property
    def profile_risk(self) -> str:
        return self._risk(self.profile_signals)

    @property
    def credential_risk(self) -> str:
        return self._risk(self.credential_signals)

    @property
    def overall_risk(self) -> str:
        all_signals = self.profile_signals + self.credential_signals
        return self._risk(all_signals)


# ---------------------------------------------------------------------------
# Check 1: account-shape (age, followers, fork ratio, velocity)
# ---------------------------------------------------------------------------

def check_profile(username: str) -> list[Signal]:
    signals: list[Signal] = []
    user = _gh_api(f"/users/{quote(username)}")
    if user is None:
        signals.append(Signal("account_lookup", "HIGH", "Cuenta no encontrada o borrada"))
        return signals

    created = datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
    age_days = (datetime.now(timezone.utc) - created).days
    followers = user.get("followers", 0)
    public_repos = user.get("public_repos", 0)

    if age_days < 14:
        signals.append(Signal("account_age", "MEDIUM", f"Cuenta creada hace {age_days} días"))
    elif age_days < 45:
        signals.append(Signal("account_age", "LOW", f"Cuenta creada hace {age_days} días"))

    if followers == 0 and age_days < 90:
        signals.append(Signal("followers", "MEDIUM", "0 followers, cuenta reciente"))

    repos = _gh_api(f"/users/{quote(username)}/repos?per_page=100&sort=created")
    if repos:
        forks = sum(1 for r in repos if r.get("fork"))
        originals = [r for r in repos if not r.get("fork")]
        fork_ratio = forks / len(repos) if repos else 0
        has_original_code = any(
            (r.get("size", 0) or 0) > 50 for r in originals
        )
        if fork_ratio > 0.8 and len(repos) >= 5 and not has_original_code:
            signals.append(
                Signal(
                    "fork_ratio",
                    "MEDIUM",
                    f"{forks}/{len(repos)} repos son forks, sin código propio sustancial",
                )
            )

        # Burst signal: several repos created within the first 24h of the
        # account itself — day-zero spray rather than organic accumulation.
        created_dates = sorted(
            datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")) for r in repos
        )
        day_zero = sum(1 for d in created_dates if (d - created).total_seconds() < 86400)
        if day_zero >= 5:
            signals.append(
                Signal(
                    "repo_burst",
                    "HIGH",
                    f"{day_zero} repos creados en las primeras 24h de la cuenta (día de creación)",
                )
            )

        # Sustained high velocity: repo creation rate too high to be organic
        # maintenance, independent of the day-zero burst.
        if age_days > 0:
            velocity = public_repos / age_days
            if velocity > 1.0 and public_repos >= 8:
                signals.append(
                    Signal(
                        "repo_velocity",
                        "MEDIUM",
                        f"{public_repos} repos en {age_days} días ({velocity:.1f}/día)",
                    )
                )

    return signals


# ---------------------------------------------------------------------------
# Check 2: credential citations (DOI, CVE, repo/SDK claims) in issue/PR body
# ---------------------------------------------------------------------------

_DOI_RE = re.compile(r"10\.\d{4,9}/[^\s\]\)]+")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_REPO_RE = re.compile(r"github\.com/([\w.-]+/[\w.-]+)")


def _check_doi(doi: str, comment_date: datetime) -> Signal:
    doi = doi.rstrip(".,;")
    data = _api(f"https://api.crossref.org/works/{quote(doi)}")
    if data is None:
        return Signal("doi", "HIGH", f"DOI citado no resuelve en Crossref: {doi}")
    try:
        parts = data["message"]["created"]["date-parts"][0]
        pub_date = datetime(parts[0], parts[1] if len(parts) > 1 else 1, parts[2] if len(parts) > 2 else 1, tzinfo=timezone.utc)
    except (KeyError, IndexError, ValueError):
        return Signal("doi", "MEDIUM", f"DOI resuelve pero sin fecha de publicación parseable: {doi}")
    if pub_date > comment_date:
        return Signal("doi", "HIGH", f"DOI publicado {pub_date.date()}, posterior al comment ({comment_date.date()})")
    return Signal("doi", "LOW", f"DOI verificado, publicado {pub_date.date()}")


def _check_cve(cve: str) -> Signal:
    data = _api(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")
    if data is None or data.get("totalResults", 0) == 0:
        return Signal("cve", "HIGH", f"CVE citado no existe en NVD: {cve}")
    return Signal("cve", "LOW", f"CVE verificado en NVD: {cve}")


def _check_repo_claim(repo_path: str, comment_date: datetime) -> Signal:
    data = _gh_api(f"/repos/{repo_path}")
    if data is None:
        return Signal("repo_claim", "HIGH", f"Repo citado no existe: {repo_path}")
    created = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
    age_at_comment = (comment_date - created).days
    if age_at_comment < 1:
        return Signal(
            "repo_claim", "HIGH",
            f"Repo {repo_path} creado el mismo día que el comment que lo cita",
        )
    if age_at_comment < 7:
        return Signal(
            "repo_claim", "MEDIUM",
            f"Repo {repo_path} tiene {age_at_comment} día(s) de antigüedad al momento del comment",
        )
    return Signal("repo_claim", "LOW", f"Repo {repo_path} con {age_at_comment} días de historia previa")


def check_credentials(body: str, comment_date: datetime) -> list[Signal]:
    signals: list[Signal] = []

    dois = set(_DOI_RE.findall(body))
    for doi in list(dois)[:3]:  # cap to avoid API hammering on adversarial input
        signals.append(_check_doi(doi, comment_date))

    cves = set(_CVE_RE.findall(body))
    for cve in list(cves)[:3]:
        signals.append(_check_cve(cve))

    repos = set(_REPO_RE.findall(body))
    for repo_path in list(repos)[:3]:
        signals.append(_check_repo_claim(repo_path, comment_date))

    return signals


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def render_comment(report: Report) -> str:
    lines = [
        "<!-- rama-contributor-check -->",
        f"{'🔴' if report.overall_risk == 'HIGH' else '🟡' if report.overall_risk == 'MEDIUM' else '🟢'} "
        f"**Contributor Check: {report.overall_risk}**",
        "",
        "| Check | Result |",
        "|-------|--------|",
        f"| Profile | {report.profile_risk} |",
        f"| Credential | {report.credential_risk} |",
        f"| **Overall** | **{report.overall_risk}** |",
    ]
    detail_signals = [s for s in report.profile_signals + report.credential_signals if s.severity != "LOW"]
    if detail_signals:
        lines.append("")
        lines.append("<details><summary>Signals</summary>")
        lines.append("")
        for s in detail_signals:
            lines.append(f"- `{s.name}` ({s.severity}): {s.detail}")
        lines.append("")
        lines.append("</details>")
    lines.append("")
    lines.append(
        "*Automated first-pass filter. Does not replace maintainer judgment — cluster/coordination "
        "patterns across repos are checked manually.*"
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--body-file", default=None, help="Path to file with issue/PR body text")
    parser.add_argument("--body", default=None, help="Issue/PR body text directly (for local testing)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    body = args.body or ""
    if args.body_file and os.path.exists(args.body_file):
        body = open(args.body_file, encoding="utf-8").read()

    report = Report(username=args.username)
    report.profile_signals = check_profile(args.username)
    report.credential_signals = check_credentials(body, datetime.now(timezone.utc))

    if args.json:
        print(json.dumps({
            "username": report.username,
            "profile_risk": report.profile_risk,
            "credential_risk": report.credential_risk,
            "overall_risk": report.overall_risk,
            "signals": [
                {"name": s.name, "severity": s.severity, "detail": s.detail}
                for s in report.profile_signals + report.credential_signals
            ],
        }, indent=2))
    else:
        print(render_comment(report))

    # Also emit GitHub Actions outputs if running in CI
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as f:
            f.write(f"risk={report.overall_risk}\n")
            f.write(f"profile-risk={report.profile_risk}\n")
            f.write(f"credential-risk={report.credential_risk}\n")


if __name__ == "__main__":
    main()
