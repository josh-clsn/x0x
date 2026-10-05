#!/usr/bin/env python3
"""Testnet survivor-rekey fixture (#1216): remove and ban, survivors decrypt, the target cannot.

For each selected variant (``plain``, ``restart``) and secure plane (``gss``: an
MlsEncrypted public-directory group on the legacy GSS plane; ``treekem``: a
``private_secure`` group), the fixture builds one fresh group whose members are
every ``--nodes`` label, then runs two cases on it:

* remove: the remover (the group creator, ``--nodes[0]``) removes ``--nodes[-2]``;
* ban:    the remover bans ``--nodes[-1]``.

At least five nodes are required, so each group has five or more members at the
removal and four or more at the ban. Each case:

1. key barrier: the remover seals a message and every other member decrypts it.
   Readiness is always proven by decrypting, never by roster state alone (#1214),
   and every joiner proves its key the same way right after its join;
2. restart variant only: the remover's ``x0xd-testnet.service`` restarts and the
   removal starts 10-20 s later (the #1190 owner-restart shape);
3. the remover removes or bans the target, then seals a message at an advanced
   secret epoch;
4. every survivor decrypts that message: the class-K share on GSS, the commit on
   TreeKEM. The rekey latency from the removal is recorded per survivor;
5. the target never decrypts it, while the survivors converge and for a further
   ``--watch-secs`` that covers the share resend and the withheld re-checks
   (D60: no later share or Welcome reaches it). On GSS the target's reported
   local secret epoch must stay below the post-removal epoch;
6. every survivor's roster stops listing the target as active;
7. GSS: the remover refuses to re-seal the current secret to the target. Ban: the
   target re-joins with an invite minted before the ban, is never seated and
   gains no key;
8. a final message sealed after all of that decrypts on every survivor and not
   on the target.

Mixed versions: nothing assumes one binary. Each node's live ``/health`` version
is recorded per node and per case role. When the eph hosts file is available
(``--hosts-json``, or ``testnet-hosts.json`` next to ``--tokens-file``), it must
name the same address per label as the tokens file, each node's live version is
checked against the binary deployed to THAT node, and per-node sha256s are
recorded. ``--expect-mixed`` also requires two or more distinct deployed
binaries among the selected nodes.

Only ``x0xd-testnet.service`` is ever addressed. Restarts need
``--allow-service-restart`` and every restarted unit is restored in ``finally``.
The remover's journal is scanned read-only after each case for
``recipient_undiscovered`` and share resends (counts and ``waited_ms`` only).
The report holds labels, status codes, response classes, epochs, timings and
hashes; never tokens, ciphertexts, invites, envelopes, log lines or bodies.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import math
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from e2e_tunnel import TunnelHandle, start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import NODES_DEFAULT, load_tokens
from e2e_vps_kv import (Api, Evidence, PollTimeout, ServiceCustody, enc, poll, safe_error_outcome,
                        safe_identifier, with_poll_timeout)
from e2e_vps_private_kv import Scenario as PrivateScenario

SERVICE = "x0xd-testnet.service"
PLANES = ("gss", "treekem")
VARIANTS = ("plain", "restart")
ACTIONS = ("remove", "ban")
MIN_NODES = 5
RESTART_LEAD_BOUNDS = (10.0, 20.0)
# Membership operations await their own publish and can outlast the default 20 s.
ACT_TIMEOUT_SECS = 60.0
HOSTS_JSON_NAME = "testnet-hosts.json"
SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)")
# The GSS (legacy plane) policy: MlsEncrypted and not hidden. The server selects
# TreeKEM only for hidden MlsEncrypted groups such as the private_secure preset.
GSS_POLICY = {
    "discoverability": "public_directory",
    "admission": "request_access",
    "confidentiality": "mls_encrypted",
    "read_access": "members_only",
    "write_access": "members_only",
}
# Any 200 from the target's decrypt means it held a usable key: a leak.
LEAK_CLASSES = frozenset({"decrypted", "wrong_plaintext"})
JOIN_STATES = frozenset({"active", "pending_authority_commit", "idle", "timed_out"})
JOIN_OUTCOMES = frozenset({"refused", "timed_out"})
JOIN_OUTCOME_REASONS = frozenset({
    "invite_secret_unknown", "invite_secret_consumed", "invite_role_exceeds_cap",
    "invite_event_before_creation", "invite_expired", "invite_not_addressed",
    "banned", "member_banned"})
# Journal markers counted on the remover after each case. The first two are
# warn-level (visible at the eph RUST_LOG=info); the share-resend lines are
# debug-level and are counted only when debug logging is enabled.
JOURNAL_PATTERNS = (
    ("recipient_undiscovered", "err_recipient_undiscovered"),
    ("welcome_fetch_failed", "failed to fetch TreeKEM Welcome blob"),
    ("share_resend_undiscovered", "secure share recipient not yet discovered"),
    ("share_write_retry", "secure share write failed"),
)
WAITED_MS_RE = re.compile(r"waited_ms[\"']?\s*[=:]\s*(\d+)")
SSH_BASE = ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            "-o", "ControlMaster=no", "-o", "ControlPath=none")
JOURNAL_SCRIPT = r'''set -u
since=$(( $(date +%s) - $1 ))
journalctl -u ''' + SERVICE + r''' --since "@$since" -o cat --no-pager 2>/dev/null \
  | grep -F -e err_recipient_undiscovered -e 'failed to fetch TreeKEM Welcome blob' \
      -e 'secure share recipient not yet discovered' -e 'secure share write failed' \
  | head -n 20000
exit 0
'''


# --------------------------------------------------------------------------- pure helpers

def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def normalize_version(value: Any) -> Optional[str]:
    """`0.46.3` from `/health`'s `0.46.3` or the deploy record's `x0xd 0.46.3`."""
    if not isinstance(value, str):
        return None
    match = VERSION_RE.search(value)
    return match.group(1) if match else None


def assign_roles(nodes: List[str]) -> Dict[str, Any]:
    """remover = first, remove target = second-last, ban target = last, survivors between."""
    if len(nodes) < MIN_NODES:
        raise ValueError(f"survivor rekey needs at least {MIN_NODES} nodes")
    if len(set(nodes)) != len(nodes):
        raise ValueError("--nodes must be distinct")
    return {"remover": nodes[0], "survivors": list(nodes[1:-2]),
            "remove_target": nodes[-2], "ban_target": nodes[-1]}


def resolve_hosts_json(explicit: Optional[str], tokens_file: str) -> Tuple[Optional[str], str]:
    """The eph run writes testnet-hosts.json next to its tokens file."""
    if explicit:
        return explicit, "explicit"
    sibling = os.path.join(os.path.dirname(os.path.abspath(tokens_file)), HOSTS_JSON_NAME)
    if os.path.isfile(sibling):
        return sibling, "sibling"
    return None, "absent"


def node_binary_map(doc: Any, endpoints: Dict[str, str]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Per-node deployed binary from an eph hosts document. Never one value for all nodes.

    Problems name labels only, never addresses.
    """
    if not isinstance(doc, dict) or doc.get("schema_version") != 1 or doc.get("kind") != "x0x-testnet-hosts":
        return {}, ["hosts file is not an x0x-testnet-hosts schema 1 document"]
    hosts = doc.get("hosts")
    if not isinstance(hosts, list):
        return {}, ["hosts file has no hosts list"]
    problems: List[str] = []
    by_label: Dict[str, Dict[str, Any]] = {}
    for host in hosts:
        if isinstance(host, dict) and isinstance(host.get("label"), str):
            if host["label"] in by_label:
                problems.append(f"hosts file lists {host['label']} twice")
            by_label[host["label"]] = host
    out: Dict[str, Dict[str, Any]] = {}
    for label, address in endpoints.items():
        host = by_label.get(label)
        if host is None:
            problems.append(f"hosts file has no entry for {label}")
            continue
        if host.get("public_ipv4") != address:
            problems.append(f"hosts file address for {label} differs from the tokens file")
            continue
        sha = host.get("daemon_sha256")
        out[label] = {"daemon_sha256": sha if isinstance(sha, str) and SHA256_HEX.fullmatch(sha) else None,
                      "deployed_version": normalize_version(host.get("daemon_version"))}
    return out, problems


def plane_of_encrypt(body: Any) -> Optional[str]:
    """TreeKEM says so; the GSS response carries a per-message nonce and no plane."""
    if not isinstance(body, dict):
        return None
    if body.get("secure_plane") == "treekem":
        return "treekem"
    nonce = body.get("nonce_b64")
    if "secure_plane" not in body and isinstance(nonce, str) and nonce:
        return "gss"
    return None


def sealed_from_encrypt(body: Any) -> Optional[Dict[str, Any]]:
    """The decrypt request body for an encrypt response, or None if it is malformed."""
    if not isinstance(body, dict) or body.get("ok") is False:
        return None
    ciphertext, epoch = body.get("ciphertext_b64"), body.get("secret_epoch")
    if not isinstance(ciphertext, str) or not ciphertext or type(epoch) is not int:
        return None
    sealed: Dict[str, Any] = {"ciphertext_b64": ciphertext, "secret_epoch": epoch}
    nonce = body.get("nonce_b64")
    if isinstance(nonce, str) and nonce:
        sealed["nonce_b64"] = nonce
    return sealed


def _text(body: Dict[str, Any], key: str) -> str:
    value = body.get(key)
    return value if isinstance(value, str) else ""


def classify_decrypt(status: Optional[int], body: Any, expected_b64: str) -> Tuple[str, Optional[int]]:
    """(response class, epoch). The epoch is the message epoch on success and the
    caller's LOCAL secret epoch on a GSS epoch mismatch; otherwise None.

    Only fixed class names leave this function, never body text.
    """
    body = body if isinstance(body, dict) else {}
    error, reason = _text(body, "error"), _text(body, "reason")
    epoch = body.get("secret_epoch")
    if status == 200:
        decrypted = body.get("ok") is not False and body.get("payload_b64") == expected_b64
        return ("decrypted" if decrypted else "wrong_plaintext"), (epoch if type(epoch) is int else None)
    if reason == "fork_quarantined":
        return "fork_quarantined", None
    if status == 409 and error.startswith("epoch mismatch"):
        local = body.get("local_epoch")
        return "epoch_mismatch", (local if type(local) is int else None)
    if status == 424:
        if error == "no shared secret available":
            return "no_secret", None
        if error.startswith("TreeKEM group not loaded"):
            return "treekem_not_loaded", None
        return "failed_dependency", None
    if status == 403:
        if error == "not a member":
            return "not_member", None
        if error == "decryption failed":
            return "decrypt_failed", None
        return "forbidden", None
    if status == 400:
        return ("treekem_decrypt_failed" if error.startswith("treekem decrypt failed") else "bad_request"), None
    if status == 404:
        return "group_not_found", None
    if status == 409:
        return "conflict", None
    return "http_other", None


def classify_reseal(status: Optional[int], body: Any) -> str:
    """`POST /groups/:id/secure/reseal` outcome. A 200 carries a sealed secret: never stored."""
    body = body if isinstance(body, dict) else {}
    if status == 200:
        return "sealed"
    if status == 404 and _text(body, "error") == "recipient is not a member":
        return "recipient_not_member"
    if status == 409 and _text(body, "reason") == "recipient_not_active":
        return "recipient_not_active"
    if status == 403:
        return "forbidden"
    if status == 424:
        return "failed_dependency"
    return "http_other" if status is not None else "transport_error"


def classify_join_attempt(status: Optional[int], body: Any) -> Dict[str, Any]:
    body = body if isinstance(body, dict) else {}
    state = body.get("join_state")
    return {"status": status,
            "join_state": state if state in JOIN_STATES else ("other" if state is not None else None)}


def classify_join_outcome(status: Optional[int], body: Any) -> Dict[str, Any]:
    """`GET /groups/:id/join-status`: allow-listed outcome and reason only."""
    body = body if isinstance(body, dict) else {}
    last = body.get("last_join_outcome")
    last = last if isinstance(last, dict) else {}
    outcome, reason = last.get("outcome"), last.get("reason")
    return {"status": status,
            "outcome": outcome if outcome in JOIN_OUTCOMES else ("other" if outcome is not None else None),
            "reason": reason if reason in JOIN_OUTCOME_REASONS else ("other" if reason is not None else None)}


def member_is_active(status: Optional[int], body: Any, agent_id: str) -> Optional[bool]:
    """None when the roster could not be read."""
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("members"), list):
        return None
    return any(isinstance(row, dict) and row.get("agent_id") == agent_id
               and str(row.get("state", "")).lower() == "active" for row in body["members"])


def restart_lead_ok(lead_seconds: float, bounds: Tuple[float, float] = RESTART_LEAD_BOUNDS) -> bool:
    return bounds[0] <= lead_seconds <= bounds[1]


def restart_observed(uptime_after: Any, since_restart_seconds: float) -> bool:
    """The daemon answering after the restart started no earlier than the restart."""
    return type(uptime_after) is int and uptime_after <= since_restart_seconds + 5


def parse_journal_matches(text: str) -> Dict[str, Any]:
    """Counts per marker and the recipient_undiscovered `waited_ms` values; no line text."""
    counts = {name: 0 for name, _ in JOURNAL_PATTERNS}
    waited: List[int] = []
    for line in text.splitlines():
        for name, needle in JOURNAL_PATTERNS:
            if needle in line:
                counts[name] += 1
                if name == "recipient_undiscovered":
                    match = WAITED_MS_RE.search(line)
                    if match:
                        waited.append(int(match.group(1)))
    return {"counts": counts, "recipient_undiscovered_waited_ms": waited[:200],
            "recipient_undiscovered_waited_ms_max": max(waited) if waited else None}


def safe_error_class(error: BaseException) -> str:
    return safe_error_outcome(error)["error_class"]


@dataclass
class RekeyTracker:
    """Probe outcomes for one post-removal message: survivors until they decrypt, the target always."""
    survivors: Tuple[str, ...]
    target: str
    started: float
    first_success: Dict[str, float] = field(default_factory=dict)
    survivor_epochs: Dict[str, Optional[int]] = field(default_factory=dict)
    survivor_classes: Dict[str, Dict[str, int]] = field(default_factory=dict)
    target_classes: Dict[str, int] = field(default_factory=dict)
    target_local_epochs: List[int] = field(default_factory=list)
    target_leaked: bool = False
    target_probes: int = 0
    last_target_probe_at: Optional[float] = None

    def observe(self, node: str, at: float, cls: str, epoch: Optional[int]) -> None:
        if node == self.target:
            self.target_probes += 1
            self.last_target_probe_at = at
            self.target_classes[cls] = self.target_classes.get(cls, 0) + 1
            if cls in LEAK_CLASSES:
                self.target_leaked = True
            elif cls == "epoch_mismatch" and epoch is not None:
                self.target_local_epochs.append(epoch)
            return
        if node not in self.survivors:
            raise ValueError(f"{node} is neither a survivor nor the target")
        if node in self.first_success:
            return
        counts = self.survivor_classes.setdefault(node, {})
        counts[cls] = counts.get(cls, 0) + 1
        if cls == "decrypted":
            self.first_success[node] = round(at - self.started, 3)
            self.survivor_epochs[node] = epoch

    def pending(self) -> List[str]:
        return [node for node in self.survivors if node not in self.first_success]

    def target_max_local_epoch(self) -> Optional[int]:
        return max(self.target_local_epochs) if self.target_local_epochs else None

    def summary(self) -> Dict[str, Any]:
        latencies = dict(self.first_success)
        slowest = max(latencies, key=lambda node: latencies[node]) if latencies else None
        return {
            "rekey_latency_s": latencies,
            "rekey_latency_max_s": latencies[slowest] if slowest else None,
            "slowest_survivor": slowest,
            "unconverged": self.pending(),
            "survivor_epochs": dict(self.survivor_epochs),
            "survivor_probe_classes": {k: dict(v) for k, v in self.survivor_classes.items()},
            "target_probe_classes": dict(self.target_classes),
            "target_probes": self.target_probes,
            "target_max_local_epoch": self.target_max_local_epoch(),
            "target_leaked": self.target_leaked,
            "target_observed_until_s": (round(self.last_target_probe_at - self.started, 3)
                                        if self.last_target_probe_at is not None else None),
        }


# --------------------------------------------------------------------------- transport

class RekeyApi(Api):
    """The shared Api with a per-call timeout (membership operations can outlast 20 s)."""

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
                timeout: float = 20.0) -> Tuple[int, Dict[str, Any]]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                payload = json.loads(response.read() or b"{}")
                return response.status, payload if isinstance(payload, dict) else {}
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read() or b"{}")
            except json.JSONDecodeError:
                payload = {}
            return error.code, payload if isinstance(payload, dict) else {}


def scan_journal(address: str, window_seconds: float, timeout: float = 45.0) -> Dict[str, Any]:
    """Read-only count of the JOURNAL_PATTERNS markers in the unit's last window."""
    window = max(1, int(math.ceil(window_seconds)))
    try:
        result = subprocess.run([*SSH_BASE, f"root@{address}", "bash", "-s", "--", str(window)],
                                input=JOURNAL_SCRIPT.encode(), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except Exception as error:
        return {"window_seconds": window, "error_class": safe_error_class(error)}
    if result.returncode != 0:
        return {"window_seconds": window, "error_class": "ssh_failed", "returncode": result.returncode}
    parsed = parse_journal_matches(result.stdout.decode("utf-8", errors="replace"))
    parsed["window_seconds"] = window
    return parsed


# --------------------------------------------------------------------------- evidence

@dataclass
class RekeyEvidence(Evidence):
    cases: List[Dict[str, Any]] = field(default_factory=list)

    def soft_check(self, label: str, condition: bool, **facts: Any) -> bool:
        """Record a check without raising, so sibling checks still run."""
        self.assertions.append({"label": label, "passed": bool(condition), **facts})
        return bool(condition)

    def report(self) -> Dict[str, Any]:
        return {"scenario": "survivor_rekey", "cases": self.cases, "polls": self.polls,
                "assertions": self.assertions}


# --------------------------------------------------------------------------- scenario

class RekeyScenario(PrivateScenario):
    """Reuses the private fixture's strict join readiness; adds the decrypt-based checks."""

    def __init__(self, clients: Dict[str, Any], evidence: RekeyEvidence, timeout: float = 120, *,
                 rekey_timeout: float = 120, watch_secs: float = 40, rejoin_watch_secs: float = 30,
                 restart_lead_secs: float = 15, probe_period: float = 1.0,
                 versions: Optional[Dict[str, Optional[str]]] = None,
                 journal_scan: Optional[Callable[[str, float], Dict[str, Any]]] = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        super().__init__(clients, evidence, timeout)
        self.e: RekeyEvidence = evidence
        self.rekey_timeout, self.watch_secs = rekey_timeout, watch_secs
        self.rejoin_watch_secs, self.restart_lead_secs = rejoin_watch_secs, restart_lead_secs
        self.probe_period = probe_period
        self.versions: Dict[str, Optional[str]] = dict(versions or {})
        self.journal_scan = journal_scan
        self.now, self.sleep = clock, sleep
        self._aids: Dict[str, str] = {}

    # -- primitives ---------------------------------------------------------

    def aid(self, node: str) -> str:
        if node not in self._aids:
            self._aids[node] = self.c[node].agent_id()
        return self._aids[node]

    def seal(self, label: str, sealer: str, gid: str, plane: str) -> Tuple[Dict[str, Any], str]:
        """Seal a fresh random message; returns (decrypt body, expected payload_b64)."""
        payload = base64.b64encode(f"x0x-rekey-{uuid.uuid4().hex}".encode()).decode()
        status, body = self.c[sealer].request("POST", f"/groups/{enc(gid)}/secure/encrypt",
                                              {"payload_b64": payload})
        sealed = sealed_from_encrypt(body) if status == 200 else None
        got = plane_of_encrypt(body) if status == 200 else None
        self.e.check(label, sealed is not None and got == plane, node=sealer, status=status,
                     plane=got, expected_plane=plane,
                     secret_epoch=sealed["secret_epoch"] if sealed else None)
        return sealed, payload  # type: ignore[return-value]

    def decrypt(self, node: str, gid: str, sealed: Dict[str, Any],
                expected: str) -> Tuple[Optional[int], str, Optional[int]]:
        try:
            status, body = self.c[node].request("POST", f"/groups/{enc(gid)}/secure/decrypt", sealed)
        except Exception as error:
            return None, f"transport:{safe_error_class(error)}", None
        cls, epoch = classify_decrypt(status, body, expected)
        return status, cls, epoch

    def await_decrypt(self, label: str, node: str, gid: str, sealed: Dict[str, Any], expected: str,
                      **context: Any) -> float:
        started = time.monotonic()

        def receipt(facts: Dict[str, Any], last: Any) -> None:
            self.e.record_poll(facts, operation="decrypt", node=node, group_id=safe_identifier(gid),
                               response_class=last[1] if isinstance(last, tuple) else None, **context)
        try:
            result = poll(label, self.timeout, lambda: self.decrypt(node, gid, sealed, expected),
                          lambda got: got[1] == "decrypted", receipt)
        except PollTimeout as error:
            self.e.assertions.append(with_poll_timeout(
                {"label": label, "passed": False, "node": node, **context}, error))
            raise
        elapsed = round(time.monotonic() - started, 3)
        self.e.check(label, True, node=node, elapsed_seconds=elapsed, secret_epoch=result[2], **context)
        return elapsed

    def await_not_active(self, label: str, observer: str, gid: str, target_aid: str) -> None:
        def receipt(facts: Dict[str, Any], _last: Any) -> None:
            self.e.record_poll(facts, operation="roster_drop", node=observer, group_id=safe_identifier(gid))
        try:
            poll(label, self.timeout,
                 lambda: self.c[observer].request("GET", f"/groups/{enc(gid)}/members"),
                 lambda got: member_is_active(got[0], got[1], target_aid) is False, receipt)
        except PollTimeout as error:
            self.e.assertions.append(with_poll_timeout({"label": label, "passed": False, "node": observer}, error))
            raise
        self.e.check(label, True, node=observer)

    def mint_invite(self, label: str, inviter: str, gid: str) -> str:
        status, body = self.c[inviter].request("POST", f"/groups/{enc(gid)}/invite", {})
        invite = body.get("invite_link") if isinstance(body, dict) else None
        self.e.check(label, status in (200, 201) and isinstance(invite, str)
                     and invite.startswith("x0x://invite/"), status=status)
        return invite  # type: ignore[return-value]

    # -- group setup --------------------------------------------------------

    def create_group(self, block: str, plane: str, owner: str) -> str:
        name = f"rekey-{plane}-{uuid.uuid4().hex[:10]}"
        request = ({"name": name, "policy": GSS_POLICY} if plane == "gss"
                   else {"name": name, "preset": "private_secure"})
        status, body = self.c[owner].request("POST", "/groups", request)
        gid = body.get("group_id") or (body.get("group") or {}).get("id")
        self.e.check(f"{block}: group created", status in (200, 201) and isinstance(gid, str) and bool(gid),
                     status=status, group_id=safe_identifier(gid))
        policy = body.get("policy") or {}
        hidden = policy.get("discoverability") == "hidden"
        self.e.check(f"{block}: group policy is MlsEncrypted on the {plane} path",
                     policy.get("confidentiality") == "mls_encrypted" and hidden == (plane == "treekem"),
                     confidentiality=policy.get("confidentiality"), discoverability=policy.get("discoverability"))
        return gid

    def join_member(self, block: str, plane: str, owner: str, member: str, gid: str) -> None:
        invite = self.mint_invite(f"{block}: invite for {member}", owner, gid)
        self._join_with_local_readiness(
            owner, member, gid, {"invite": invite},
            accepted_label=f"{block}: {member} join accepted",
            readiness_label=f"{block}: {member} on owner roster and locally active",
            operation="rekey_join_readiness")
        # #1214: roster + local active is not key readiness. Prove the key.
        sealed, payload = self.seal(f"{block}: remover seals post-join message for {member}", owner, gid, plane)
        self.await_decrypt(f"{block}: {member} key installed after join (decrypts post-join message)",
                           member, gid, sealed, payload, phase="join_key")

    def key_barrier(self, case: str, plane: str, sealer: str, gid: str, members: List[str]) -> int:
        sealed, payload = self.seal(f"{case}: remover seals key-barrier message", sealer, gid, plane)
        for member in members:
            self.await_decrypt(f"{case}: {member} holds the current key (decrypts barrier message)",
                               member, gid, sealed, payload, phase="barrier")
        return sealed["secret_epoch"]

    # -- the case -----------------------------------------------------------

    def restart_before_act(self, case: str, remover: str,
                           restart_fn: Callable[[str], None]) -> Tuple[float, Dict[str, Any]]:
        status, before = self.c[remover].request("GET", "/health")
        aid_before = self.aid(remover)
        restart_fn(remover)
        restarted_at = self.now()
        poll(f"{case}: remover health after restart", 60,
             lambda: self.c[remover].request("GET", "/health"),
             lambda got: got[0] == 200 and got[1].get("ok") is True,
             lambda facts, _last: self.e.record_poll(facts, operation="health", node=remover))
        healthy_s = round(self.now() - restarted_at, 3)
        status_after, after = self.c[remover].request("GET", "/health")
        aid_after = self.c[remover].agent_id()
        version_after = normalize_version(after.get("version")) if status_after == 200 else None
        uptime_after = after.get("uptime_secs") if status_after == 200 else None
        facts = {"health_after_restart_s": healthy_s,
                 "uptime_before_s": before.get("uptime_secs") if status == 200 else None,
                 "uptime_after_s": uptime_after, "version_after": version_after}
        self.e.check(f"{case}: remover restarted and kept its identity",
                     aid_after == aid_before and restart_observed(uptime_after, self.now() - restarted_at),
                     node=remover, **facts)
        if version_after is not None:
            self.versions[remover] = version_after
        return restarted_at, facts

    def act(self, action: str, remover: str, gid: str, target_aid: str) -> Tuple[Optional[int], Dict[str, Any]]:
        method, path, body = (("DELETE", f"/groups/{enc(gid)}/members/{target_aid}", None) if action == "remove"
                              else ("POST", f"/groups/{enc(gid)}/ban/{target_aid}", {}))
        try:
            return self.c[remover].request(method, path, body, timeout=ACT_TIMEOUT_SECS)
        except Exception as error:
            return None, {"transport_error_class": safe_error_class(error)}

    def seal_after(self, case: str, action: str, plane: str, remover: str, gid: str,
                   before_epoch: int) -> Tuple[Dict[str, Any], str, int]:
        """A post-removal message at an epoch above the barrier's; retried briefly."""
        deadline = self.now() + 30
        attempts = 0
        while True:
            attempts += 1
            sealed, payload = self.seal(f"{case}: remover seals post-{action} message", remover, gid, plane)
            if sealed["secret_epoch"] > before_epoch or self.now() >= deadline:
                break
            self.sleep(1.0)
        self.e.check(f"{case}: remover secret epoch advanced past the barrier",
                     sealed["secret_epoch"] > before_epoch, epoch_before=before_epoch,
                     epoch_after=sealed["secret_epoch"], attempts=attempts)
        return sealed, payload, attempts

    def _timed_decrypt(self, node: str, gid: str, sealed: Dict[str, Any],
                       expected: str) -> Tuple[str, float, str, Optional[int]]:
        _status, cls, epoch = self.decrypt(node, gid, sealed, expected)
        return node, self.now(), cls, epoch

    def _probe_round(self, pool: concurrent.futures.Executor, tracker: RekeyTracker, nodes: List[str],
                     gid: str, sealed: Dict[str, Any], expected: str) -> None:
        started = self.now()
        futures = [pool.submit(self._timed_decrypt, node, gid, sealed, expected) for node in nodes]
        for future in concurrent.futures.as_completed(futures):
            node, at, cls, epoch = future.result()
            tracker.observe(node, at, cls, epoch)
        rest = self.probe_period - (self.now() - started)
        if rest > 0:
            self.sleep(rest)

    def converge(self, gid: str, sealed: Dict[str, Any], expected: str, survivors: List[str],
                 target: str, acted_at: float) -> RekeyTracker:
        """Round-robin: every pending survivor and the target each round, then the target alone."""
        tracker = RekeyTracker(tuple(survivors), target, acted_at)
        deadline = acted_at + self.rekey_timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(survivors) + 1) as pool:
            while tracker.pending() and self.now() < deadline and not tracker.target_leaked:
                self._probe_round(pool, tracker, [*tracker.pending(), target], gid, sealed, expected)
            watch_until = self.now() + self.watch_secs
            while self.now() < watch_until and not tracker.target_leaked:
                self._probe_round(pool, tracker, [target], gid, sealed, expected)
        return tracker

    def banned_rejoin(self, case: str, plane: str, remover: str, target: str, gid: str,
                      invite: str) -> Dict[str, Any]:
        """The banned target re-joins with an invite minted before the ban."""
        try:
            status, body = self.c[target].request("POST", "/groups/join", {"invite": invite})
        except Exception as error:
            status, body = None, {"transport_error_class": safe_error_class(error)}
        attempt = classify_join_attempt(status, body)
        sealed, payload = self.seal(f"{case}: remover seals post-rejoin-attempt message", remover, gid, plane)
        target_aid = self.aid(target)
        seated = leaked = False
        classes: Dict[str, int] = {}
        deadline = self.now() + self.rejoin_watch_secs
        while self.now() < deadline and not (seated or leaked):
            rstatus, roster = self.c[remover].request("GET", f"/groups/{enc(gid)}/members")
            seated = member_is_active(rstatus, roster, target_aid) is True
            _status, cls, _epoch = self.decrypt(target, gid, sealed, payload)
            classes[cls] = classes.get(cls, 0) + 1
            leaked = cls in LEAK_CLASSES
            self.sleep(self.probe_period)
        try:
            ostatus, obody = self.c[target].request("GET", f"/groups/{enc(gid)}/join-status")
        except Exception:
            ostatus, obody = None, {}
        outcome = classify_join_outcome(ostatus, obody)
        result = {"attempt": attempt, "join_status": outcome, "probe_classes": classes,
                  "watch_seconds": self.rejoin_watch_secs}
        self.e.soft_check(f"{case}: banned {target} re-join is never seated", not seated,
                          node=target, attempt=attempt, join_status=outcome)
        self.e.soft_check(f"{case}: banned {target} gains no key from the re-join attempt", not leaked,
                          node=target, probe_classes=classes)
        if seated or leaked:
            raise AssertionError(f"{case}: banned re-join check failed")
        return result

    def run_case(self, block: str, variant: str, plane: str, action: str, gid: str, remover: str,
                 target: str, survivors: List[str], restart_fn: Optional[Callable[[str], None]]) -> None:
        case = f"{block}/{action}"
        case_started = self.now()
        record: Dict[str, Any] = {
            "case": case, "variant": variant, "plane": plane, "action": action,
            "group_id": safe_identifier(gid), "remover": remover, "target": target,
            "survivors": list(survivors), "started_utc": utc_now(), "outcome": "failed",
            "versions": {"remover": self.versions.get(remover), "target": self.versions.get(target),
                         "survivors": {node: self.versions.get(node) for node in survivors}},
        }
        self.e.cases.append(record)
        print(f"[rekey] {case}: remover={remover} target={target} survivors={','.join(survivors)}", flush=True)
        try:
            self.e.check(f"{case}: group has at least four members before the {action}",
                         len(survivors) + 2 >= 4, members=len(survivors) + 2)
            target_aid = self.aid(target)
            record["epoch_before"] = self.key_barrier(case, plane, remover, gid, [*survivors, target])
            pre_ban_invite = (self.mint_invite(f"{case}: remover mints an invite before the ban", remover, gid)
                              if action == "ban" else None)
            if restart_fn is not None:
                restarted_at, record["restart"] = self.restart_before_act(case, remover, restart_fn)
                record["versions"]["remover"] = self.versions.get(remover)
                wait = restarted_at + self.restart_lead_secs - self.now()
                if wait > 0:
                    self.sleep(wait)
                lead = round(self.now() - restarted_at, 3)
                record["restart"]["lead_seconds"] = lead
                lead_ok = restart_lead_ok(lead)
                facts: Dict[str, Any] = {"lead_seconds": lead, "bounds": list(RESTART_LEAD_BOUNDS)}
                if not lead_ok:
                    facts["verdict"] = "inconclusive"
                self.e.check(f"{case}: {action} starts 10-20 s after the remover restart", lead_ok, **facts)
            else:
                record["restart"] = None

            act_started = self.now()
            status, body = self.act(action, remover, gid, target_aid)
            acted_at = self.now()
            record["act"] = {"status": status, "seconds": round(acted_at - act_started, 3)}
            self.e.check(f"{case}: {action} of {target} accepted",
                         status == 200 and body.get("ok") is not False, status=status,
                         seconds=record["act"]["seconds"])

            sealed, payload, attempts = self.seal_after(case, action, plane, remover, gid, record["epoch_before"])
            post_epoch = sealed["secret_epoch"]
            record["epoch_after"] = post_epoch
            record["seal_after_seconds"] = round(self.now() - acted_at, 3)

            tracker = self.converge(gid, sealed, payload, survivors, target, acted_at)
            summary = tracker.summary()
            record["rekey"] = summary
            print(f"[rekey] {case}: latency_s={summary['rekey_latency_s']} "
                  f"unconverged={summary['unconverged']} target={summary['target_probe_classes']}", flush=True)
            ok = True
            for node in survivors:
                latency = tracker.first_success.get(node)
                epoch = tracker.survivor_epochs.get(node)
                ok &= self.e.soft_check(
                    f"{case}: {node} rekeyed and decrypts the post-{action} message",
                    latency is not None and (epoch is None or epoch >= post_epoch),
                    node=node, latency_seconds=latency, secret_epoch=epoch, post_epoch=post_epoch,
                    probe_classes=summary["survivor_probe_classes"].get(node, {}),
                    version=self.versions.get(node))
            ok &= self.e.soft_check(
                f"{case}: {target} cannot decrypt the post-{action} message", not tracker.target_leaked,
                node=target, probe_classes=summary["target_probe_classes"])
            max_local = tracker.target_max_local_epoch()
            ok &= self.e.soft_check(
                f"{case}: no post-{action} key reaches {target} during the watch (D60)",
                not tracker.target_leaked and (max_local is None or max_local < post_epoch),
                node=target, watch_seconds=self.watch_secs,
                observed_until_seconds=summary["target_observed_until_s"],
                target_max_local_epoch=max_local, post_epoch=post_epoch)
            if not ok:
                raise AssertionError(f"{case}: rekey checks failed")

            for node in [remover, *survivors]:
                self.await_not_active(f"{case}: {node} roster no longer lists {target} as active",
                                      node, gid, target_aid)

            if plane == "gss":
                try:
                    rstatus, rbody = self.c[remover].request(
                        "POST", f"/groups/{enc(gid)}/secure/reseal", {"recipient": target_aid})
                except Exception:
                    rstatus, rbody = None, {}
                reseal = classify_reseal(rstatus, rbody)
                record["reseal"] = {"status": rstatus, "response_class": reseal}
                self.e.check(f"{case}: remover refuses to seal the current secret to {target}",
                             reseal != "sealed", status=rstatus, response_class=reseal)

            if pre_ban_invite is not None:
                record["rejoin"] = self.banned_rejoin(case, plane, remover, target, gid, pre_ban_invite)

            final, final_payload = self.seal(f"{case}: remover seals final message", remover, gid, plane)
            for node in survivors:
                self.await_decrypt(f"{case}: {node} decrypts the final message", node, gid, final,
                                   final_payload, phase="final")
            _status, cls, _epoch = self.decrypt(target, gid, final, final_payload)
            self.e.check(f"{case}: {target} cannot decrypt the final message", cls not in LEAK_CLASSES,
                         node=target, response_class=cls)
            record["outcome"] = "passed"
        finally:
            record["finished_utc"] = utc_now()
            record["seconds"] = round(self.now() - case_started, 3)
            if self.journal_scan is not None:
                try:
                    record["journal_remover"] = self.journal_scan(remover, self.now() - case_started + 2)
                except Exception as error:
                    record["journal_remover"] = {"error_class": safe_error_class(error)}

    def run_block(self, variant: str, plane: str, roles: Dict[str, Any],
                  restart_fn: Optional[Callable[[str], None]]) -> None:
        block = f"{variant}/{plane}"
        remover = roles["remover"]
        joiners = [*roles["survivors"], roles["remove_target"], roles["ban_target"]]
        print(f"[rekey] {block}: creating group, {len(joiners)} joiners", flush=True)
        gid = self.create_group(block, plane, remover)
        for member in joiners:
            self.join_member(block, plane, remover, member, gid)
        members = [remover, *joiners]
        targets = {"remove": roles["remove_target"], "ban": roles["ban_target"]}
        for action in ACTIONS:
            target = targets[action]
            survivors = [node for node in members if node not in (remover, target)]
            self.run_case(block, variant, plane, action, gid, remover, target, survivors,
                          restart_fn if variant == "restart" else None)
            members.remove(target)


# --------------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network", choices=["test"], required=True)
    parser.add_argument("--tokens-file", required=True)
    parser.add_argument("--hosts-json", default=None,
                        help="eph testnet-hosts.json (default: the one next to --tokens-file, if present)")
    parser.add_argument("--nodes", nargs="+", default=NODES_DEFAULT[:5],
                        help="REMOVER SURVIVOR... REMOVE_TARGET BAN_TARGET (at least five)")
    parser.add_argument("--variant", action="append", choices=VARIANTS,
                        help="repeatable; default: plain then restart")
    parser.add_argument("--plane", action="append", choices=PLANES, help="repeatable; default: gss then treekem")
    parser.add_argument("--local-port-base", type=int, default=23900)
    parser.add_argument("--poll-timeout", type=float, default=120)
    parser.add_argument("--rekey-timeout", type=float, default=120)
    parser.add_argument("--watch-secs", type=float, default=40)
    parser.add_argument("--rejoin-watch-secs", type=float, default=30)
    parser.add_argument("--restart-lead-secs", type=float, default=15)
    parser.add_argument("--expect-mixed", action="store_true",
                        help="require two or more distinct deployed binaries among --nodes (needs the hosts file)")
    parser.add_argument("--allow-service-restart", action="store_true")
    parser.add_argument("--no-journal-scan", action="store_true")
    parser.add_argument("--report", required=True)
    return parser


def parse_and_validate(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse argv and check everything that needs no network. Exits 2 on a bad invocation."""
    parser = build_parser()
    args = parser.parse_args(argv)
    args.variant = args.variant or list(VARIANTS)
    args.plane = args.plane or list(PLANES)
    for name in ("variant", "plane"):
        values = getattr(args, name)
        if len(set(values)) != len(values):
            parser.error(f"each --{name} may be selected only once")
    if "restart" in args.variant and not args.allow_service_restart:
        parser.error("the restart variant requires --allow-service-restart")
    if not restart_lead_ok(args.restart_lead_secs):
        parser.error("--restart-lead-secs must be within 10-20 s")
    try:
        args.roles = assign_roles(args.nodes)
    except ValueError as error:
        parser.error(str(error))
    try:
        tokens = load_tokens(args.tokens_file, var_prefix="TEST")
    except OSError:
        parser.error("--tokens-file is missing or unreadable")
    missing = [node for node in args.nodes if node not in tokens]
    if missing:
        parser.error(f"missing testnet token/IP entries: {missing}")
    args.endpoints = {node: tokens[node][0] for node in args.nodes}
    args.api_tokens = {node: tokens[node][1] for node in args.nodes}
    if len(set(args.endpoints.values())) != len(args.nodes):
        parser.error("--nodes must resolve to distinct endpoints")
    path, source = resolve_hosts_json(args.hosts_json, args.tokens_file)
    args.hosts_json_source, args.hosts_json_sha256, args.node_binaries = source, None, {}
    if path is not None:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            doc = json.loads(raw)
        except (OSError, ValueError):
            parser.error("--hosts-json is unreadable or not JSON")
        args.hosts_json_sha256 = hashlib.sha256(raw).hexdigest()
        args.node_binaries, problems = node_binary_map(doc, args.endpoints)
        if problems:
            parser.error("hosts file does not describe these nodes: " + "; ".join(problems))
    if args.expect_mixed and not args.node_binaries:
        parser.error("--expect-mixed needs the eph hosts file")
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_and_validate(argv)
    roles: Dict[str, Any] = args.roles
    remover = roles["remover"]
    started_utc, started = utc_now(), time.monotonic()
    tunnels: Dict[str, TunnelHandle] = {}
    clients: Dict[str, RekeyApi] = {}
    evidence = RekeyEvidence()
    custody = ServiceCustody(args.endpoints)
    succeeded = False
    live_versions: Dict[str, Optional[str]] = {}
    journal_totals: Dict[str, Any] = {}

    def await_health(node: str) -> None:
        client = clients.get(node)
        if client is None:
            raise RuntimeError(f"no owned API client available to verify {node} health")
        poll(f"{node} health", 60, lambda: client.request("GET", "/health"),
             lambda result: result[0] == 200 and result[1].get("ok") is True)

    def journal(node: str, window: float) -> Dict[str, Any]:
        return scan_journal(args.endpoints[node], window)

    try:
        for index, node in enumerate(args.nodes):
            tunnel = start_ssh_tunnel(args.endpoints[node], args.local_port_base + index, remote_port=13600)
            tunnels[node] = tunnel
            clients[node] = RekeyApi(f"http://127.0.0.1:{tunnel.local_port}", args.api_tokens[node])
        identities = {node: clients[node].agent_id() for node in args.nodes}
        if len(set(identities.values())) != len(args.nodes):
            raise RuntimeError("survivor rekey requires distinct daemon agent identities")
        if "restart" in args.variant:
            custody.require_active(remover)

        for node in args.nodes:
            status, body = clients[node].request("GET", "/health")
            live_versions[node] = normalize_version(body.get("version")) if status == 200 else None
        evidence.check("live version recorded for every node", all(live_versions.values()),
                       versions=dict(live_versions))
        for node, deployed in args.node_binaries.items():
            evidence.check(f"{node} live version matches the binary deployed to it",
                           deployed["deployed_version"] in (None, live_versions.get(node)),
                           live_version=live_versions.get(node), deployed_version=deployed["deployed_version"],
                           daemon_sha256=deployed["daemon_sha256"])
        if args.expect_mixed:
            shas = {entry["daemon_sha256"] for entry in args.node_binaries.values() if entry["daemon_sha256"]}
            evidence.check("selected nodes run two or more distinct binaries", len(shas) >= 2,
                           distinct_binaries=len(shas))

        scenario = RekeyScenario(
            clients, evidence, args.poll_timeout, rekey_timeout=args.rekey_timeout,
            watch_secs=args.watch_secs, rejoin_watch_secs=args.rejoin_watch_secs,
            restart_lead_secs=args.restart_lead_secs, versions=live_versions,
            journal_scan=None if args.no_journal_scan else journal)

        def restart(node: str) -> None:
            custody.restart(node)

        for variant in args.variant:
            for plane in args.plane:
                try:
                    scenario.run_block(variant, plane, roles, restart if variant == "restart" else None)
                except Exception as error:
                    # Class only: str(error) could echo a server body or bearer token.
                    evidence.assertions.append(with_poll_timeout(
                        {"label": f"{variant}/{plane}: block aborted", "passed": False,
                         "error_class": type(error).__name__}, error))
        succeeded = True
    except Exception as error:
        evidence.assertions.append(with_poll_timeout({"label": "harness", "passed": False,
                                                      "error_class": type(error).__name__}, error))
    finally:
        for error in custody.restore(await_health):
            evidence.assertions.append({"label": error, "passed": False})
            succeeded = False
        if not args.no_journal_scan:
            window = time.monotonic() - started + 5
            for node in args.nodes:
                journal_totals[node] = scan_journal(args.endpoints[node], window)
        for tunnel in list(tunnels.values()):
            try:
                stop_ssh_tunnel(tunnel)
            except Exception as error:
                evidence.assertions.append({"label": f"cleanup: {type(error).__name__}", "passed": False})
                succeeded = False
        report = evidence.report()
        shas = sorted({entry["daemon_sha256"] for entry in args.node_binaries.values() if entry["daemon_sha256"]})
        report.update({
            "issue": 1216, "started_utc": started_utc, "finished_utc": utc_now(),
            "roles": roles, "variants": args.variant, "planes": args.plane,
            "settings": {"poll_timeout": args.poll_timeout, "rekey_timeout": args.rekey_timeout,
                         "watch_secs": args.watch_secs, "rejoin_watch_secs": args.rejoin_watch_secs,
                         "restart_lead_secs": args.restart_lead_secs, "expect_mixed": args.expect_mixed},
            "hosts_json_source": args.hosts_json_source, "hosts_json_sha256": args.hosts_json_sha256,
            "node_versions": {node: {"live_version": live_versions.get(node),
                                     **args.node_binaries.get(node, {"daemon_sha256": None,
                                                                     "deployed_version": None})}
                              for node in args.nodes},
            "distinct_binaries": shas,
            "mixed_binaries": len(shas) > 1 or len({v for v in live_versions.values() if v}) > 1,
            "journal_totals": journal_totals,
        })
        try:
            with open(args.report, "w", encoding="utf-8") as output:
                json.dump(report, output, indent=2)
        except Exception:
            succeeded = False
    passed = succeeded and bool(evidence.cases) and all(item["passed"] for item in evidence.assertions)
    print(f"[rekey] {'PASS' if passed else 'FAIL'}: {sum(1 for a in evidence.assertions if a['passed'])}/"
          f"{len(evidence.assertions)} assertions, {len(evidence.cases)} cases", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
