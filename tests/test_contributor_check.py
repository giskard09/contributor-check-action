"""Offline tests: the GitHub API is stubbed, no network."""
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import contributor_check as cc  # noqa: E402

NOW = datetime(2026, 11, 21, tzinfo=timezone.utc)

# Shape of a Dependabot PR body: release notes plus GitHub docs links.
DEPENDABOT_BODY = """Bumps [x](https://github.com/probityai/agent-evidence-vectors) from 0.36.3 to 0.37.0.
Dependabot will resolve any conflicts. You can read more at
https://docs.github.com/en/github/managing-security-vulnerabilities and
[docs](https://docs.github.com/en/github/administering-a-repository).
"""


class ReproFalsePositive(unittest.TestCase):
    def test_docs_github_com_is_not_a_repo_citation(self):
        found = cc._REPO_RE.findall("see https://docs.github.com/en/github/foo")
        self.assertEqual(found, [])

    def test_real_repo_link_still_matches(self):
        self.assertEqual(cc._REPO_RE.findall("https://github.com/probityai/agent-evidence-vectors/pull/1"),
                         ["probityai/agent-evidence-vectors"])
        self.assertEqual(cc._REPO_RE.findall("(github.com/a/b)"), ["a/b"])

    def test_subdomain_variants_do_not_match(self):
        for u in ("https://docs.github.com/en/github", "https://gist.github.com/u/abc",
                  "https://raw.github.com/u/r", "https://my-github.com/u/r"):
            self.assertEqual(cc._REPO_RE.findall(u), [], u)


class BotAuthors(unittest.TestCase):
    def test_is_bot_login(self):
        self.assertTrue(cc.is_bot_login("dependabot[bot]"))
        self.assertTrue(cc.is_bot_login("github-actions[bot]"))
        self.assertFalse(cc.is_bot_login("dependabot"))      # a human can pick this name
        self.assertFalse(cc.is_bot_login("someone"))

    def test_bot_body_produces_no_credential_signals_and_never_calls_api(self):
        with mock.patch.object(cc, "_gh_api", side_effect=AssertionError("API called")), \
             mock.patch.object(cc, "_api", side_effect=AssertionError("API called")):
            self.assertEqual(cc.check_credentials(DEPENDABOT_BODY, NOW, is_bot=True), [])

    def test_human_missing_repo_is_still_high(self):
        # control: the HIGH signal for a fabricated repo is unchanged for non-bots
        with mock.patch.object(cc, "_gh_api", return_value=None):
            sigs = cc.check_credentials("see github.com/ghost/nonexistent", NOW)
        self.assertEqual([(s.name, s.severity) for s in sigs], [("repo_claim", "HIGH")])

    def test_human_with_dependabot_body_only_checks_the_real_repo(self):
        calls = []
        def fake(path):
            calls.append(path)
            return {"created_at": "2025-01-01T00:00:00Z"}
        with mock.patch.object(cc, "_gh_api", side_effect=fake):
            sigs = cc.check_credentials(DEPENDABOT_BODY, NOW)
        self.assertEqual(calls, ["/repos/probityai/agent-evidence-vectors"])
        self.assertTrue(all(s.severity == "LOW" for s in sigs))


if __name__ == "__main__":
    unittest.main()
