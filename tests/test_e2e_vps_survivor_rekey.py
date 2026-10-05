"""Pure-python tests for the #1216 survivor-rekey fixture. No daemon, no network."""
import base64
import hashlib
import json
import os
import tempfile
import threading
import unittest
import uuid

import e2e_vps_survivor_rekey as h
from e2e_vps_kv import PollTimeout

LABELS = ["nyc", "sfo", "helsinki", "nuremberg", "singapore"]
GID = "f" * 64


class FakeClock:
    """Monotonic time that moves only when the scenario sleeps."""

    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)


class FakeNet:
    """One group on one secure plane, shared by every fake daemon."""

    def __init__(self, plane, labels, *, lag=None, leak_to=None, withhold_join_key=(),
                 reseal_leaks=False, seat_banned=False, on_health=None):
        self.plane, self.labels, self.lock = plane, list(labels), threading.Lock()
        self.epoch = 0
        self.state = {label: None for label in labels}
        self.have = {label: None for label in labels}
        self.agents = {label: hashlib.sha256(label.encode()).hexdigest() for label in labels}
        self.by_agent = {aid: label for label, aid in self.agents.items()}
        self.lag, self.pending = dict(lag or {}), {}
        self.leak_to, self.withhold_join_key = leak_to, set(withhold_join_key)
        self.reseal_leaks, self.seat_banned, self.on_health = reseal_leaks, seat_banned, on_health
        self.messages, self.uptime, self.restarts = {}, {label: 1000 for label in labels}, []
        self.secrets = set()  # strings that must never reach a report

    def node(self, label):
        return FakeNode(self, label)

    def restart(self, label):
        self.uptime[label] = 0
        self.restarts.append(label)

    def _rotate(self, exclude):
        self.epoch += 1
        owner = self.labels[0]
        self.have[owner] = self.epoch
        for label in self.labels:
            if label == owner or label in exclude or self.state[label] != "active":
                continue
            delay = self.lag.get(label, 0)
            if delay <= 0:
                self.have[label] = self.epoch
            else:
                self.pending[label] = (delay, self.epoch)
        if self.leak_to is not None:
            self.have[self.leak_to] = self.epoch

    def _tick(self, label):
        if label in self.pending:
            remaining, epoch = self.pending[label]
            if remaining <= 1:
                del self.pending[label]
                self.have[label] = epoch
            else:
                self.pending[label] = (remaining - 1, epoch)

    def handle(self, label, method, path, body):
        g = f"/groups/{GID}"
        if method == "GET" and path == "/agent":
            return 200, {"agent_id": self.agents[label]}
        if method == "GET" and path == "/health":
            if self.on_health is not None:
                self.on_health(label)
            return 200, {"ok": True, "version": "0.46.3", "uptime_secs": self.uptime[label]}
        if method == "POST" and path == "/groups":
            self.state[label], self.epoch, self.have[label] = "active", 1, 1
            policy = (dict(h.GSS_POLICY) if self.plane == "gss"
                      else {"discoverability": "hidden", "confidentiality": "mls_encrypted"})
            return 201, {"ok": True, "group_id": GID, "policy": policy}
        if method == "POST" and path == f"{g}/invite":
            link = f"x0x://invite/fake-{uuid.uuid4().hex}"
            self.secrets.add(link)
            return 200, {"ok": True, "invite_link": link}
        if method == "POST" and path == "/groups/join":
            if self.state[label] == "banned":
                if self.seat_banned:
                    self.state[label], self.have[label] = "active", self.epoch
                return 200, {"ok": True, "group_id": GID, "join_state": "pending_authority_commit"}
            self.state[label] = "active"
            if self.plane == "treekem":  # the add commit moves every member to a new epoch
                self.epoch += 1
                for other in self.labels:
                    if self.state[other] == "active" and self.have[other] is not None:
                        self.have[other] = self.epoch
            self.have[label] = None if label in self.withhold_join_key else self.epoch
            return 200, {"ok": True, "group_id": GID, "join_state": "active"}
        if method == "GET" and path == f"{g}/members":
            return 200, {"members": [{"agent_id": self.agents[x], "state": self.state[x]}
                                     for x in self.labels if self.state[x] in ("active", "banned")]}
        if method == "GET" and path == g:
            if self.state[label] == "active":
                return 200, {"group_id": GID, "membership_state": "active"}
            return 404, {"error": "group not found"}
        if method == "GET" and path == f"{g}/join-status":
            return 200, {"join_state": "idle", "last_join_outcome": {"outcome": "refused", "reason": "banned"}}
        if method == "POST" and path == f"{g}/secure/encrypt":
            if self.state[label] != "active" or self.have[label] is None:
                return 403, {"ok": False, "error": "not a member"}
            ciphertext = base64.b64encode(uuid.uuid4().bytes).decode()
            self.messages[ciphertext] = (self.have[label], body["payload_b64"])
            self.secrets.add(ciphertext)
            if self.plane == "gss":
                return 200, {"ok": True, "ciphertext_b64": ciphertext, "nonce_b64": "bm9uY2Vub25jZQ==",
                             "secret_epoch": self.have[label]}
            return 200, {"ok": True, "ciphertext_b64": ciphertext, "secret_epoch": self.have[label],
                         "secure_plane": "treekem"}
        if method == "POST" and path == f"{g}/secure/decrypt":
            self._tick(label)
            if self.state[label] not in ("active", "banned") and label != self.leak_to:
                return 403, {"ok": False, "error": "not a member"}
            epoch, payload = self.messages[body["ciphertext_b64"]]
            have = self.have[label]
            if self.plane == "gss":
                if have is None:
                    return 424, {"ok": False, "error": "no shared secret available"}
                if have != epoch:
                    return 409, {"ok": False, "error": "epoch mismatch — re-share required",
                                 "local_epoch": have, "ciphertext_epoch": epoch}
                return 200, {"ok": True, "payload_b64": payload, "secret_epoch": epoch}
            if have is None:
                return 424, {"ok": False, "error": "TreeKEM group not loaded — restart or re-share required"}
            if have < epoch:
                return 400, {"ok": False, "error": "treekem decrypt failed: unknown epoch"}
            return 200, {"ok": True, "payload_b64": payload, "secret_epoch": have, "secure_plane": "treekem"}
        if method == "DELETE" and path.startswith(f"{g}/members/"):
            target = self.by_agent[path.rsplit("/", 1)[1]]
            self.state[target] = "removed"
            self._rotate(exclude=(target,))
            return 200, {"ok": True, "removed_member": self.agents[target]}
        if method == "POST" and path.startswith(f"{g}/ban/"):
            target = self.by_agent[path.rsplit("/", 1)[1]]
            self.state[target] = "banned"
            self._rotate(exclude=(target,))
            return 200, {"ok": True, "revision": 9}
        if method == "POST" and path == f"{g}/secure/reseal":
            target = self.by_agent[body["recipient"]]
            if self.reseal_leaks or self.state[target] == "active":
                self.secrets.add("SECRET-ENVELOPE")
                return 200, {"ok": True, "envelope_b64": "SECRET-ENVELOPE"}
            if self.state[target] == "banned":
                return 409, {"ok": False, "error": "recipient is not active", "reason": "recipient_not_active"}
            return 404, {"ok": False, "error": "recipient is not a member"}
        return 500, {"error": f"unhandled {method} {path}"}


class FakeNode:
    def __init__(self, net, label):
        self.net, self.label = net, label

    def agent_id(self):
        return self.net.agents[self.label]

    def request(self, method, path, body=None, timeout=20.0):
        with self.net.lock:
            return self.net.handle(self.label, method, path, body)


def scenario(plane, poll_timeout=0.5, **net_kwargs):
    net = FakeNet(plane, LABELS, **net_kwargs)
    clock = FakeClock()
    scans = []

    def journal(node, window):
        scans.append((node, window))
        return {"counts": {"recipient_undiscovered": 0}, "window_seconds": int(window)}

    s = h.RekeyScenario({label: net.node(label) for label in LABELS}, h.RekeyEvidence(), poll_timeout,
                        rekey_timeout=30, watch_secs=10, rejoin_watch_secs=5, restart_lead_secs=15,
                        probe_period=1.0, versions={label: "0.46.3" for label in LABELS},
                        journal_scan=journal, clock=clock.now, sleep=clock.sleep)
    return s, net, clock, scans


def failed_labels(s):
    return [row["label"] for row in s.e.assertions if not row["passed"]]


class PureHelperTests(unittest.TestCase):
    def test_normalize_version(self):
        self.assertEqual(h.normalize_version("x0xd 0.46.3"), "0.46.3")
        self.assertEqual(h.normalize_version("0.46.3"), "0.46.3")
        self.assertEqual(h.normalize_version("x0xd 0.47.0-rc.1"), "0.47.0-rc.1")
        self.assertIsNone(h.normalize_version("x0xd"))
        self.assertIsNone(h.normalize_version(None))

    def test_assign_roles(self):
        roles = h.assign_roles(LABELS)
        self.assertEqual(roles, {"remover": "nyc", "survivors": ["sfo", "helsinki"],
                                 "remove_target": "nuremberg", "ban_target": "singapore"})
        with self.assertRaises(ValueError):
            h.assign_roles(LABELS[:4])
        with self.assertRaises(ValueError):
            h.assign_roles(["nyc", "sfo", "nyc", "helsinki", "sydney"])

    def test_plane_and_sealed_from_encrypt(self):
        gss = {"ok": True, "ciphertext_b64": "Y3Q=", "nonce_b64": "bm9uY2U=", "secret_epoch": 3}
        tk = {"ok": True, "ciphertext_b64": "Y3Q=", "secret_epoch": 7, "secure_plane": "treekem"}
        self.assertEqual(h.plane_of_encrypt(gss), "gss")
        self.assertEqual(h.plane_of_encrypt(tk), "treekem")
        self.assertIsNone(h.plane_of_encrypt({"ciphertext_b64": "Y3Q=", "secret_epoch": 1}))
        self.assertIsNone(h.plane_of_encrypt({"secure_plane": "gss", "nonce_b64": "x"}))
        self.assertEqual(h.sealed_from_encrypt(gss), {"ciphertext_b64": "Y3Q=", "nonce_b64": "bm9uY2U=",
                                                      "secret_epoch": 3})
        self.assertEqual(h.sealed_from_encrypt(tk), {"ciphertext_b64": "Y3Q=", "secret_epoch": 7})
        self.assertIsNone(h.sealed_from_encrypt({"ciphertext_b64": "Y3Q=", "secret_epoch": "3"}))
        self.assertIsNone(h.sealed_from_encrypt({"ok": False, "ciphertext_b64": "Y3Q=", "secret_epoch": 3}))
        self.assertIsNone(h.sealed_from_encrypt({"ciphertext_b64": "Y3Q=", "secret_epoch": True}))

    def test_classify_decrypt(self):
        want = "cGF5bG9hZA=="
        cases = [
            ((200, {"ok": True, "payload_b64": want, "secret_epoch": 4}), ("decrypted", 4)),
            ((200, {"ok": True, "payload_b64": "b3RoZXI=", "secret_epoch": 4}), ("wrong_plaintext", 4)),
            ((409, {"error": "epoch mismatch — re-share required", "local_epoch": 3}), ("epoch_mismatch", 3)),
            ((409, {"error": "x", "reason": "fork_quarantined"}), ("fork_quarantined", None)),
            ((409, {"error": "other"}), ("conflict", None)),
            ((424, {"error": "no shared secret available"}), ("no_secret", None)),
            ((424, {"error": "TreeKEM group not loaded — restart or re-share required"}),
             ("treekem_not_loaded", None)),
            ((424, {"error": "else"}), ("failed_dependency", None)),
            ((403, {"error": "not a member"}), ("not_member", None)),
            ((403, {"error": "decryption failed"}), ("decrypt_failed", None)),
            ((403, {"error": "x", "reason": "fork_quarantined"}), ("fork_quarantined", None)),
            ((403, {"error": "rider"}), ("forbidden", None)),
            ((400, {"error": "treekem decrypt failed: bad"}), ("treekem_decrypt_failed", None)),
            ((400, {"error": "invalid base64 nonce"}), ("bad_request", None)),
            ((404, {"error": "group not found"}), ("group_not_found", None)),
            ((500, {"error": "boom"}), ("http_other", None)),
            ((409, ["not", "a", "dict"]), ("conflict", None)),
        ]
        for (status, body), expected in cases:
            with self.subTest(status=status, body=body):
                self.assertEqual(h.classify_decrypt(status, body, want), expected)

    def test_classify_reseal_and_join(self):
        self.assertEqual(h.classify_reseal(200, {"envelope_b64": "S"}), "sealed")
        self.assertEqual(h.classify_reseal(404, {"error": "recipient is not a member"}), "recipient_not_member")
        self.assertEqual(h.classify_reseal(409, {"reason": "recipient_not_active"}), "recipient_not_active")
        self.assertEqual(h.classify_reseal(403, {}), "forbidden")
        self.assertEqual(h.classify_reseal(500, {}), "http_other")
        self.assertEqual(h.classify_reseal(None, {}), "transport_error")
        self.assertEqual(h.classify_join_attempt(200, {"join_state": "pending_authority_commit"}),
                         {"status": 200, "join_state": "pending_authority_commit"})
        self.assertEqual(h.classify_join_attempt(409, {"join_state": "<script>"}),
                         {"status": 409, "join_state": "other"})
        self.assertEqual(h.classify_join_outcome(200, {"last_join_outcome": {"outcome": "refused",
                                                                             "reason": "banned"}}),
                         {"status": 200, "outcome": "refused", "reason": "banned"})
        self.assertEqual(h.classify_join_outcome(404, {"last_join_outcome": {"outcome": "x", "reason": "free text"}}),
                         {"status": 404, "outcome": "other", "reason": "other"})
        self.assertEqual(h.classify_join_outcome(200, {}), {"status": 200, "outcome": None, "reason": None})

    def test_member_is_active(self):
        roster = {"members": [{"agent_id": "a", "state": "Active"}, {"agent_id": "b", "state": "banned"}]}
        self.assertTrue(h.member_is_active(200, roster, "a"))
        self.assertFalse(h.member_is_active(200, roster, "b"))
        self.assertFalse(h.member_is_active(200, roster, "c"))
        self.assertIsNone(h.member_is_active(500, roster, "a"))
        self.assertIsNone(h.member_is_active(200, {"members": None}, "a"))

    def test_restart_bounds(self):
        self.assertTrue(h.restart_lead_ok(10.0))
        self.assertTrue(h.restart_lead_ok(20.0))
        self.assertFalse(h.restart_lead_ok(9.99))
        self.assertFalse(h.restart_lead_ok(20.01))
        self.assertTrue(h.restart_observed(3, 4.0))
        self.assertFalse(h.restart_observed(500, 4.0))
        self.assertFalse(h.restart_observed(None, 4.0))
        self.assertFalse(h.restart_observed(True, 4.0))

    def test_parse_journal_matches_counts_without_text(self):
        text = "\n".join([
            'WARN x0x::direct: pinned send: no verified source stage="send" agent_prefix=ab12 '
            'outcome="err_recipient_undiscovered" waited_ms=1500',
            '{"fields":{"outcome":"err_recipient_undiscovered","waited_ms":20}}',
            "WARN failed to fetch TreeKEM Welcome blob after retries group=deadbeef",
            "DEBUG secure share recipient not yet discovered; resending: recipient_undiscovered",
            "DEBUG secure share write failed; retrying: timeout",
            "INFO unrelated line",
        ])
        parsed = h.parse_journal_matches(text)
        self.assertEqual(parsed["counts"], {"recipient_undiscovered": 2, "welcome_fetch_failed": 1,
                                            "share_resend_undiscovered": 1, "share_write_retry": 1})
        self.assertEqual(parsed["recipient_undiscovered_waited_ms"], [1500, 20])
        self.assertEqual(parsed["recipient_undiscovered_waited_ms_max"], 1500)
        self.assertNotIn("deadbeef", json.dumps(parsed))
        self.assertEqual(h.parse_journal_matches("")["recipient_undiscovered_waited_ms_max"], None)

    def test_rekey_tracker(self):
        tracker = h.RekeyTracker(("sfo", "helsinki"), "nuremberg", started=100.0)
        tracker.observe("sfo", 100.5, "epoch_mismatch", 3)
        tracker.observe("helsinki", 100.6, "decrypted", 4)
        tracker.observe("nuremberg", 100.6, "epoch_mismatch", 3)
        self.assertEqual(tracker.pending(), ["sfo"])
        tracker.observe("sfo", 102.25, "decrypted", 4)
        tracker.observe("sfo", 103.0, "epoch_mismatch", 3)  # ignored after success
        tracker.observe("nuremberg", 104.0, "not_member", None)
        summary = tracker.summary()
        self.assertEqual(summary["rekey_latency_s"], {"helsinki": 0.6, "sfo": 2.25})
        self.assertEqual(summary["slowest_survivor"], "sfo")
        self.assertEqual(summary["rekey_latency_max_s"], 2.25)
        self.assertEqual(summary["survivor_probe_classes"]["sfo"], {"epoch_mismatch": 1, "decrypted": 1})
        self.assertEqual(summary["target_probe_classes"], {"epoch_mismatch": 1, "not_member": 1})
        self.assertEqual(summary["target_max_local_epoch"], 3)
        self.assertFalse(summary["target_leaked"])
        self.assertEqual(summary["target_observed_until_s"], 4.0)
        tracker.observe("nuremberg", 105.0, "wrong_plaintext", 4)
        self.assertTrue(tracker.target_leaked)
        with self.assertRaises(ValueError):
            tracker.observe("sydney", 105.0, "decrypted", 4)


class HostsFileTests(unittest.TestCase):
    def doc(self, **override):
        hosts = [{"label": label, "public_ipv4": f"203.0.113.{i + 1}",
                  "daemon_sha256": ("a" if i % 2 else "b") * 64,
                  "daemon_version": "x0xd 0.46.3" if i % 2 else "x0xd 0.46.2"}
                 for i, label in enumerate(LABELS)]
        doc = {"schema_version": 1, "kind": "x0x-testnet-hosts", "hosts": hosts}
        doc.update(override)
        return doc

    def endpoints(self):
        return {label: f"203.0.113.{i + 1}" for i, label in enumerate(LABELS)}

    def test_per_node_map_never_collapses_to_one_binary(self):
        mapped, problems = h.node_binary_map(self.doc(), self.endpoints())
        self.assertEqual(problems, [])
        self.assertEqual(mapped["nyc"], {"daemon_sha256": "b" * 64, "deployed_version": "0.46.2"})
        self.assertEqual(mapped["sfo"], {"daemon_sha256": "a" * 64, "deployed_version": "0.46.3"})
        self.assertEqual(len({entry["daemon_sha256"] for entry in mapped.values()}), 2)

    def test_problems_name_labels_not_addresses(self):
        endpoints = self.endpoints()
        endpoints["sfo"] = "198.51.100.9"
        endpoints["sydney"] = "198.51.100.10"
        _mapped, problems = h.node_binary_map(self.doc(), endpoints)
        self.assertEqual(problems, ["hosts file address for sfo differs from the tokens file",
                                    "hosts file has no entry for sydney"])
        self.assertNotIn("198.51.100", " ".join(problems))
        self.assertTrue(h.node_binary_map({"kind": "other"}, endpoints)[1])
        self.assertTrue(h.node_binary_map(self.doc(hosts="x"), endpoints)[1])
        dup = self.doc()
        dup["hosts"].append(dict(dup["hosts"][0]))
        self.assertIn("hosts file lists nyc twice", h.node_binary_map(dup, self.endpoints())[1])

    def test_resolve_hosts_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tokens = os.path.join(tmp, "vps-tokens-test.env")
            open(tokens, "w").close()
            self.assertEqual(h.resolve_hosts_json(None, tokens), (None, "absent"))
            sibling = os.path.join(tmp, "testnet-hosts.json")
            open(sibling, "w").close()
            self.assertEqual(h.resolve_hosts_json(None, tokens), (sibling, "sibling"))
            self.assertEqual(h.resolve_hosts_json("/x/hosts.json", tokens), ("/x/hosts.json", "explicit"))


class ArgumentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tokens = os.path.join(self.tmp.name, "vps-tokens-test.env")
        with open(self.tokens, "w") as handle:
            for i, label in enumerate(LABELS + ["sydney"]):
                handle.write(f'TEST_{label.upper()}_IP="203.0.113.{i + 1}"\nTEST_{label.upper()}_TK="{"0" * 63}{i}"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def argv(self, *extra):
        return ["--network", "test", "--tokens-file", self.tokens, "--report", "/dev/null", *extra]

    def test_eph_table_argv_parses(self):
        args = h.parse_and_validate(self.argv("--nodes", *LABELS, "--variant", "plain", "--variant", "restart",
                                              "--allow-service-restart"))
        self.assertEqual(args.variant, ["plain", "restart"])
        self.assertEqual(args.plane, ["gss", "treekem"])
        self.assertEqual(args.roles["remover"], "nyc")
        self.assertEqual(args.hosts_json_source, "absent")
        self.assertEqual(args.node_binaries, {})

    def test_defaults_run_both_variants_and_need_restart_permission(self):
        with self.assertRaises(SystemExit):
            h.parse_and_validate(self.argv())
        args = h.parse_and_validate(self.argv("--variant", "plain"))
        self.assertEqual(args.nodes, LABELS)

    def test_rejections(self):
        for extra in (("--variant", "plain", "--nodes", *LABELS[:4]),
                      ("--variant", "plain", "--nodes", "nyc", "sfo", "nyc", "helsinki", "sydney"),
                      ("--variant", "plain", "--nodes", *LABELS[:4], "london"),
                      ("--variant", "plain", "--variant", "plain"),
                      ("--variant", "plain", "--restart-lead-secs", "25"),
                      ("--variant", "plain", "--expect-mixed")):
            with self.subTest(extra=extra), self.assertRaises(SystemExit):
                h.parse_and_validate(self.argv(*extra))

    def test_sibling_hosts_file_is_validated_and_mapped(self):
        hosts = [{"label": label, "public_ipv4": f"203.0.113.{i + 1}", "daemon_sha256": str(i % 2) * 64,
                  "daemon_version": "x0xd 0.46.3"} for i, label in enumerate(LABELS + ["sydney"])]
        path = os.path.join(self.tmp.name, "testnet-hosts.json")
        with open(path, "w") as handle:
            json.dump({"schema_version": 1, "kind": "x0x-testnet-hosts", "hosts": hosts}, handle)
        args = h.parse_and_validate(self.argv("--variant", "plain", "--expect-mixed"))
        self.assertEqual(args.hosts_json_source, "sibling")
        self.assertEqual(len(args.hosts_json_sha256), 64)
        self.assertEqual(set(args.node_binaries), set(LABELS))
        hosts[1]["public_ipv4"] = "198.51.100.1"
        with open(path, "w") as handle:
            json.dump({"schema_version": 1, "kind": "x0x-testnet-hosts", "hosts": hosts}, handle)
        with self.assertRaises(SystemExit):
            h.parse_and_validate(self.argv("--variant", "plain"))


class ScenarioTests(unittest.TestCase):
    def run_block(self, plane, variant="plain", **net_kwargs):
        s, net, clock, scans = scenario(plane, **net_kwargs)
        restart = net.restart if variant == "restart" else None
        s.run_block(variant, plane, h.assign_roles(LABELS), restart)
        return s, net, clock, scans

    def test_block_passes_on_both_planes_and_variants(self):
        for plane in h.PLANES:
            for variant in h.VARIANTS:
                with self.subTest(plane=plane, variant=variant):
                    s, net, _clock, scans = self.run_block(plane, variant, lag={"sfo": 3})
                    self.assertEqual(failed_labels(s), [])
                    self.assertEqual([c["case"] for c in s.e.cases],
                                     [f"{variant}/{plane}/remove", f"{variant}/{plane}/ban"])
                    remove, ban = s.e.cases
                    self.assertEqual(remove["survivors"], ["sfo", "helsinki", "singapore"])
                    self.assertEqual(ban["survivors"], ["sfo", "helsinki"])
                    for case in s.e.cases:
                        self.assertEqual(case["outcome"], "passed")
                        self.assertGreater(case["epoch_after"], case["epoch_before"])
                        self.assertEqual(case["rekey"]["rekey_latency_s"]["sfo"], 2.0)
                        self.assertEqual(case["rekey"]["slowest_survivor"], "sfo")
                        self.assertEqual(case["rekey"]["unconverged"], [])
                        self.assertFalse(case["rekey"]["target_leaked"])
                        self.assertGreaterEqual(case["rekey"]["target_probes"], 10)
                        self.assertEqual(case["versions"]["survivors"]["sfo"], "0.46.3")
                        self.assertIn("journal_remover", case)
                        if variant == "restart":
                            self.assertEqual(case["restart"]["lead_seconds"], 15.0)
                        else:
                            self.assertIsNone(case["restart"])
                        self.assertEqual("reseal" in case, plane == "gss")
                    self.assertEqual("rejoin" in ban, True)
                    self.assertNotIn("rejoin", remove)
                    self.assertEqual(net.restarts, ["nyc", "nyc"] if variant == "restart" else [])
                    self.assertEqual([node for node, _ in scans], ["nyc", "nyc"])
                    if plane == "gss":
                        self.assertEqual(remove["reseal"]["response_class"], "recipient_not_member")
                        self.assertEqual(ban["reseal"]["response_class"], "recipient_not_active")
                        self.assertEqual(ban["rekey"]["target_max_local_epoch"], ban["epoch_before"])
                    labels = [row["label"] for row in s.e.assertions]
                    self.assertIn(f"{variant}/{plane}: helsinki key installed after join "
                                  f"(decrypts post-join message)", labels)
                    self.assertIn(f"{variant}/{plane}/ban: no post-ban key reaches singapore during the watch (D60)",
                                  labels)
                    report = json.dumps(s.e.report())
                    for secret in net.secrets:
                        self.assertNotIn(secret, report)

    def test_leak_to_removed_member_fails_the_d60_checks(self):
        s, *_ = scenario("gss", leak_to="nuremberg")
        with self.assertRaises(AssertionError):
            s.run_block("plain", "gss", h.assign_roles(LABELS), None)
        self.assertEqual(failed_labels(s), [
            "plain/gss/remove: nuremberg cannot decrypt the post-remove message",
            "plain/gss/remove: no post-remove key reaches nuremberg during the watch (D60)"])
        self.assertEqual(s.e.cases[0]["outcome"], "failed")
        self.assertIn("journal_remover", s.e.cases[0])

    def test_survivor_that_never_rekeys_fails_but_target_is_still_watched(self):
        s, *_ = scenario("treekem", lag={"helsinki": 10 ** 6})
        with self.assertRaises(AssertionError):
            s.run_block("plain", "treekem", h.assign_roles(LABELS), None)
        self.assertEqual(failed_labels(s),
                         ["plain/treekem/remove: helsinki rekeyed and decrypts the post-remove message"])
        rekey = s.e.cases[0]["rekey"]
        self.assertEqual(rekey["unconverged"], ["helsinki"])
        self.assertGreaterEqual(rekey["target_observed_until_s"], 30.0)

    def test_join_readiness_needs_the_key_not_the_roster(self):
        s, *_ = scenario("treekem", poll_timeout=0.05, withhold_join_key=("helsinki",))
        with self.assertRaises(PollTimeout):
            s.run_block("plain", "treekem", h.assign_roles(LABELS), None)
        row = s.e.assertions[-1]
        self.assertEqual(row["label"], "plain/treekem: helsinki key installed after join (decrypts post-join message)")
        self.assertFalse(row["passed"])
        self.assertIn("poll_timeout", row)
        # The roster-and-local-active barrier itself was satisfied: only the key proof failed.
        self.assertTrue(any(p.get("label") == "plain/treekem: helsinki on owner roster and locally active"
                            and p.get("outcome") == "accepted" for p in s.e.polls))

    def test_reseal_to_removed_member_fails_and_envelope_never_recorded(self):
        s, net, *_ = scenario("gss", reseal_leaks=True)
        with self.assertRaises(AssertionError):
            s.run_block("plain", "gss", h.assign_roles(LABELS), None)
        self.assertEqual(failed_labels(s),
                         ["plain/gss/remove: remover refuses to seal the current secret to nuremberg"])
        self.assertNotIn("SECRET-ENVELOPE", json.dumps(s.e.report()))

    def test_seated_banned_member_fails_the_rejoin_check(self):
        s, *_ = scenario("treekem", seat_banned=True)
        with self.assertRaises(AssertionError):
            s.run_block("plain", "treekem", h.assign_roles(LABELS), None)
        failed = failed_labels(s)
        self.assertIn("plain/treekem/ban: banned singapore re-join is never seated", failed)
        self.assertEqual(s.e.cases[1]["outcome"], "failed")

    def test_slow_restart_is_inconclusive(self):
        holder = {}

        def slow_health(label):
            if label == "nyc" and holder["net"].uptime["nyc"] == 0 and not holder.get("slowed"):
                holder["slowed"] = True
                holder["clock"].sleep(25)

        s, net, clock, _ = scenario("gss", on_health=slow_health)
        holder.update(net=net, clock=clock)
        with self.assertRaises(AssertionError):
            s.run_block("restart", "gss", h.assign_roles(LABELS), net.restart)
        row = next(r for r in s.e.assertions if not r["passed"])
        self.assertEqual(row["label"], "restart/gss/remove: remove starts 10-20 s after the remover restart")
        self.assertEqual(row["verdict"], "inconclusive")
        self.assertEqual(row["lead_seconds"], 25.0)


if __name__ == "__main__":
    unittest.main()
