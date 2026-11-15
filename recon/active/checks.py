from __future__ import annotations

import asyncio
import ssl
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import ClassVar
from urllib.parse import urlsplit

from recon.active.adapters import Outcome, build_adapter
from recon.active.authorization import AuthorizationFile
from recon.active.context import ActiveContext, BudgetExceeded
from recon.active.models import ActiveCheckResult
from recon.analysis.findings import LIMITATIONS, RECOMMENDATIONS, lookup_text
from recon.models import CollectionError, Confidence, Finding, ModuleStatus, Severity
from recon.utils import redact_secret, redact_url

S, C = Severity, Confidence


class ActiveCheck(ABC):
    '''
    Base class for an active check.
    '''

    check_id: ClassVar[str]
    description: ClassVar[str]

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Reason this check cannot run given the authorization, or None if it can.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: A human-readable skip reason, or None.
        '''
        return None

    @abstractmethod
    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Execute the check.
        Parameters:
            ctx (ActiveContext): Shared client, budget and rate limiter.
        Returns:
            ActiveCheckResult: Findings, request count and status.
        Raises:
            Exception: Any unexpected failure; the orchestrator converts it to a FAILED result.
        '''

    def _result(self, target: str, started: datetime, *, status: ModuleStatus,
                findings: list[Finding] | None = None, requests: int = 0,
                errors: list[CollectionError] | None = None, skipped: str | None = None) -> ActiveCheckResult:
        '''
        Build a result for this check.
        Parameters:
            target (str): What was tested.
            started (datetime): When the check began.
            status (ModuleStatus): Outcome status.
            findings (list[Finding] | None): Findings produced.
            requests (int): Requests this check made.
            errors (list[CollectionError] | None): Errors recorded.
            skipped (str | None): Skip reason, if skipped.
        Returns:
            ActiveCheckResult: The populated result.
        '''
        now = datetime.now(UTC)
        return ActiveCheckResult(
            check_id=self.check_id, status=status, target=target, description=self.description,
            findings=findings or [], requests_made=requests, skipped_reason=skipped,
            started_at=started, finished_at=now,
            duration_ms=round((now - started).total_seconds() * 1000, 2), errors=errors or [])

    def _finding(self, code: str, subject: str, *, title: str, description: str, severity: Severity,
                 evidence: list[str], source: str, confidence: Confidence = C.HIGH,
                 recommendation: str | None = None) -> Finding:
        '''
        Build an active finding.
        Parameters:
            code (str): Finding code, e.g. 'active.supabase_rls_open'.
            subject (str): What the finding is about.
            title (str): Short title.
            description (str): Explanation.
            severity (Severity): Severity.
            evidence (list[str]): Supporting evidence (already redacted).
            source (str): Where it came from.
            confidence (Confidence): Confidence.
            recommendation (str | None): Suggested remediation.
        Returns:
            Finding: The finding.
        '''
        return Finding(id=f"{code}:{subject}", category="active", title=title, description=description,
                       severity=severity, confidence=confidence, evidence=evidence, source=source,
                       subject=subject, timestamp=datetime.now(UTC),
                       recommendation=recommendation or lookup_text(RECOMMENDATIONS, code),
                       limitations=lookup_text(LIMITATIONS, code))


class BackendReadAccessCheck(ActiveCheck):
    '''
    Checks whether a public, client-side credential can read data it should not — across any backend.
    '''

    check_id: ClassVar[str] = "backend_read_access"
    description: ClassVar[str] = ("Issues one read-only probe per operator-listed backend resource using only a "
                                  "public/client-side credential; a resource that returns data indicates "
                                  "anonymous read access is not restricted.")

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Require at least one backend with an in-scope host, resources, and a non-privileged credential.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: Skip reason, or None.
        '''
        if not auth.backends:
            return "no 'backends' configured in the authorization"
        for backend in auth.backends:
            adapter = build_adapter(backend)
            if not auth.scope.allows(adapter.host):
                continue
            if not adapter.resources():
                continue
            if adapter.credential_guard() is not None:
                continue
            return None
        return ("no backend has an in-scope host with resources and a public (non-privileged) credential; "
                "add the backend's host to scope.hosts and list its resources")

    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Probe each in-scope backend's resources and flag any that return data to a public credential.
        Parameters:
            ctx (ActiveContext): Shared context.
        Returns:
            ActiveCheckResult: One finding per readable resource.
        '''
        started: datetime = datetime.now(UTC)
        findings: list[Finding] = []
        errors: list[CollectionError] = []
        start_count: int = ctx.check_count(self.check_id)

        for backend in ctx.auth.backends:
            adapter = build_adapter(backend)
            host: str = adapter.host
            if not ctx.auth.scope.allows(host):
                continue
            guard: str | None = adapter.credential_guard()
            if guard is not None:
                errors.append(CollectionError(module=self.check_id, target=f"{adapter.kind}:{host}", error_type="privileged_credential", message=guard))
                continue
            if await self._probe_backend(ctx, adapter, findings, errors):
                break

        requests: int = ctx.check_count(self.check_id) - start_count
        status: ModuleStatus = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return self._result("backends", started, status=status, findings=findings, requests=requests, errors=errors)

    async def _probe_backend(self, ctx: ActiveContext, adapter, findings: list[Finding], errors: list[CollectionError]) -> bool:
        '''
        Probe every resource of one backend, appending findings/errors. Returns True if the budget ran out.
        Parameters:
            ctx (ActiveContext): Shared context.
            adapter (BackendAdapter): The adapter for this backend.
            findings (list[Finding]): Finding accumulator.
            errors (list[CollectionError]): Error accumulator.
        Returns:
            bool: True if the request budget was exhausted (stop the whole check).
        '''
        for resource in adapter.resources():
            probe = adapter.build_probe(resource)
            target: str = f"{adapter.kind}:{adapter.label(resource)}"
            try:
                resp = await ctx.request(self.check_id, probe.method, probe.url, content=probe.content, headers=probe.headers, note=probe.note)
            except BudgetExceeded as exc:
                errors.append(CollectionError(module=self.check_id, target=target, error_type="budget_exceeded", message=str(exc)))
                return True
            if resp is None:
                errors.append(CollectionError(module=self.check_id, target=target, error_type="request_failed", message="no response"))
                continue
            outcome = adapter.interpret(resource, resp)
            if outcome.outcome is Outcome.OPEN:
                findings.append(self._open_finding(adapter, resource, probe, outcome))
        return False

    def _open_finding(self, adapter, resource, probe, outcome) -> Finding:
        '''
        Build the high-severity finding for a resource that was readable with a public credential.
        Parameters:
            adapter (BackendAdapter): The adapter.
            resource (Any): The resource that was readable.
            probe (ProbeRequest): The request that was sent.
            outcome (ProbeOutcome): The interpreted outcome (carries a detail string).
        Returns:
            Finding: The finding.
        '''
        label: str = adapter.label(resource)
        cred: str | None = adapter.credential()
        cred_line: str = (f"credential: {redact_secret(cred)}" if cred else "credential: none (tested the unauthenticated/open case)")
        return self._finding(
            "active.backend_read_access_open", f"{adapter.kind}:{adapter.host}/{label}",
            title=f"{adapter.kind} resource '{label}' is readable with a public client-side credential",
            description=(f"A read-only probe of this {adapter.kind} resource returned data using only a "
                         "public, client-side credential (the kind shipped in a site's JavaScript). Backend "
                         "authorization — row-level security, database/storage rules, or role permissions — is "
                         "not restricting anonymous reads, so anyone holding the public credential can read it."),
            severity=S.HIGH,
            evidence=[f"backend: {adapter.kind}", f"resource: {label}",
                      f"{probe.method} {redact_url(probe.url)} → {outcome.detail}", cred_line],
            source=f"{adapter.kind} read probe with a public client-side credential")


class FunctionUrlReachabilityCheck(ActiveCheck):
    '''
    Checks whether function/edge URLs respond without authentication.
    '''

    check_id: ClassVar[str] = "function_url_reachability"
    description: ClassVar[str] = ("Sends one minimal, side-effect-free request per listed function URL and records "
                                  "whether it is reachable without authentication.")

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Require at least one listed function URL whose host is in scope.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: Skip reason, or None.
        '''
        if not auth.function_urls:
            return "no 'function_urls' listed in the authorization"

        if not any(auth.scope.allows(urlsplit(t.url).hostname) for t in auth.function_urls):
            return "none of the listed function_urls have a host in scope.hosts"

        return None

    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Probe each in-scope function URL once and classify its auth posture.
        Parameters:
            ctx (ActiveContext): Shared context.
        Returns:
            ActiveCheckResult: Findings for endpoints reachable without authentication.
        '''
        started: datetime = datetime.now(UTC)
        findings: list[Finding] = []
        errors: list[CollectionError] = []
        start_count: int = ctx.check_count(self.check_id)

        for target in ctx.auth.function_urls:
            host = urlsplit(target.url).hostname

            if not ctx.auth.scope.allows(host): continue
            method: str = target.method.upper()
            # Only ever send an empty body; never a payload that could create state.
            body: bytes | None = b"{}" if method in ("POST", "PUT", "PATCH") else None
            headers: dict[str, str] | None = {"Content-Type": "application/json"} if body else None

            try:
                resp = await ctx.request(self.check_id, method, target.url, content=body, headers=headers, note="function URL reachability")

            except BudgetExceeded as exc:
                errors.append(CollectionError(module=self.check_id, target=target.url, error_type="budget_exceeded", message=str(exc)))
                break

            if resp is None:
                errors.append(CollectionError(module=self.check_id, target=target.url, error_type="request_failed", message="no response"))
                continue

            findings.extend(self._classify(target, method, resp.status_code))

        requests: int = ctx.check_count(self.check_id) - start_count
        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS

        return self._result("function URLs", started, status=status, findings=findings, requests=requests, errors=errors)

    def _classify(self, target, method: str, status_code: int) -> list[Finding]:
        '''
        Turn a response status into a finding based on auth posture and the operator's state-changing label.
        Parameters:
            target (FunctionUrlTarget): The endpoint.
            method (str): Method used.
            status_code (int): Response status.
        Returns:
            list[Finding]: Zero or one finding.
        '''
        subject: str = redact_url(target.url)
        evidence: list[str] = [f"{method} {subject} → HTTP {status_code}"]
        if status_code in (401, 403): return []

        if 200 <= status_code < 400:
            if target.state_changing:
                return [self._finding(
                    "active.endpoint_open", subject,
                    title="State-changing endpoint reachable without authentication",
                    description="The operator labeled this endpoint as state-changing, and it accepted an "
                                "unauthenticated request. An attacker may be able to invoke it directly. This "
                                "check sent only an empty body, so no action was triggered by the probe itself.",
                    severity=S.HIGH, evidence=evidence, source="single unauthenticated reachability probe",
                    recommendation="Require authentication/authorization on this endpoint, or verify it is "
                                   "intended to be public and safe to call anonymously.")]

            return [self._finding(
                "active.endpoint_reachable", subject,
                title="Function endpoint reachable without authentication",
                description="The endpoint responded to an unauthenticated request. This is informational: "
                            "confirm it is meant to be publicly reachable.",
                severity=S.INFORMATIONAL, evidence=evidence, confidence=C.MEDIUM,
                source="single unauthenticated reachability probe")]

        return []


class ClientIpHeaderTrustCheck(ActiveCheck):
    '''
    Checks whether an endpoint changes its decision based on client-supplied IP headers.
    '''

    check_id: ClassVar[str] = "client_ip_header_trust"
    description: ClassVar[str] = ("Sends a baseline request and copies with spoofed client-IP headers "
                                  "(X-Forwarded-For, etc.) to see whether the server trusts them for its decision.")

    IP_HEADERS: ClassVar[tuple[str, ...]] = (
        "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP", "CF-Connecting-IP",
        "True-Client-IP", "Fastly-Client-IP", "X-Cluster-Client-IP")

    TEST_IPS: ClassVar[tuple[str, ...]] = ("127.0.0.1", "10.0.0.1")

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Require at least one listed ip-trust endpoint whose host is in scope.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: Skip reason, or None.
        '''
        if not auth.ip_trust_endpoints: return "no 'ip_trust_endpoints' listed in the authorization"
        if not any(auth.scope.allows(urlsplit(t.url).hostname) for t in auth.ip_trust_endpoints): return "none of the listed ip_trust_endpoints have a host in scope.hosts"
        return None

    def _headers(self, ip: str) -> dict[str, str]: return {**{h: ip for h in self.IP_HEADERS}, "Forwarded": f"for={ip}"}

    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        For each in-scope endpoint, compare a baseline response to spoofed-IP-header copies.
        Parameters:
            ctx (ActiveContext): Shared context.
        Returns:
            ActiveCheckResult: Findings for endpoints whose decision changes with the headers.
        '''
        started = datetime.now(UTC)
        findings: list[Finding] = []
        errors: list[CollectionError] = []
        start_count = ctx.check_count(self.check_id)

        for target in ctx.auth.ip_trust_endpoints:
            if not ctx.auth.scope.allows(urlsplit(target.url).hostname): continue

            method = target.method.upper()
            try:
                baseline = await ctx.request(self.check_id, method, target.url, note="ip-trust baseline")
                if baseline is None:
                    errors.append(CollectionError(module=self.check_id, target=target.url,  error_type="request_failed", message="baseline had no response"))
                    continue

                changed: list[tuple[str, int]] = []
                for ip in self.TEST_IPS:
                    resp = await ctx.request(self.check_id, method, target.url, headers=self._headers(ip), note=f"ip-trust spoofed headers ({ip})")
                    
                    if resp is not None and resp.status_code != baseline.status_code: changed.append((ip, resp.status_code))

            except BudgetExceeded as exc:
                errors.append(CollectionError(module=self.check_id, target=target.url, error_type="budget_exceeded", message=str(exc)))
                break

            if target.access_control and 200 <= baseline.status_code < 400:
                findings.append(self._finding(
                    "active.access_control_open", redact_url(target.url),
                    title="Access-controlled endpoint reachable without authentication",
                    description="The operator labeled this endpoint as access-controlled, but an ordinary "
                                "unauthenticated request returned a success status. It is reachable with no "
                                "restriction at all (independent of any header trick).",
                    severity=S.HIGH, confidence=C.MEDIUM,
                    evidence=[f"{method} {redact_url(target.url)} (no spoofed headers) → HTTP {baseline.status_code}"],
                    source="single unauthenticated baseline request"))
            
            if changed: findings.append(self._trust_finding(target, baseline.status_code, changed))

        requests = ctx.check_count(self.check_id) - start_count
        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return self._result("ip-trust endpoints", started, status=status, findings=findings, requests=requests, errors=errors)

    def _trust_finding(self, target, baseline_status: int, changed: list[tuple[str, int]]) -> Finding:
        '''
        Build the finding for an endpoint that trusts client-supplied IP headers.
        Parameters:
            target (IpTrustTarget): The endpoint.
            baseline_status (int): Status without spoofed headers.
            changed (list[tuple[str, int]]): (test IP, resulting status) for each change observed.
        Returns:
            Finding: The finding (high when it flips an access/rate decision).
        '''
        subject = redact_url(target.url)
        bypass = target.access_control or (baseline_status in (401, 403, 429)
                                           and any(200 <= s < 400 for _, s in changed))
        evidence = [f"baseline: HTTP {baseline_status}",
                    *[f"with client-IP headers = {ip}: HTTP {status}" for ip, status in changed],
                    f"headers tested: {', '.join(self.IP_HEADERS)}, Forwarded"]
        if bypass:
            return self._finding(
                "active.client_ip_header_bypass", subject,
                title="Access/rate decision changes with client-supplied IP headers",
                description="The server returned a different status when client-controllable IP headers "
                            "(X-Forwarded-For and similar) were set. If an allowlist or rate limit keys on these "
                            "headers, an attacker can bypass it by setting them. No packets were forged; these are "
                            "ordinary request headers anyone can send.",
                severity=S.HIGH, confidence=C.MEDIUM, evidence=evidence,
                source="baseline vs. spoofed-client-IP-header requests",
                recommendation="Derive the client IP only from the trusted proxy's connection, not from "
                               "client-supplied headers; strip inbound X-Forwarded-For/X-Real-IP at the edge.")
        return self._finding(
            "active.client_ip_header_trusted", subject,
            title="Response varies with client-supplied IP headers",
            description="The server's response changed when client-IP headers were set. This may be benign "
                        "(e.g. geo/logging) but confirm no access or rate decision depends on these headers.",
            severity=S.LOW, confidence=C.MEDIUM, evidence=evidence,
            source="baseline vs. spoofed-client-IP-header requests")


class EmailEndpointRateLimitCheck(ActiveCheck):
    '''
    Checks whether an operator-opted-in email/notification endpoint rate-limits a small burst.
    '''

    check_id: ClassVar[str] = "email_endpoint_rate_limit"
    description: ClassVar[str] = ("Sends a small, operator-approved, test-marked burst (≤10) to a confirmed-safe "
                                  "endpoint to check whether throttling kicks in; never used against endpoints "
                                  "that could deliver to a real recipient.")
    THROTTLE_CODES: ClassVar[frozenset[int]] = frozenset({429, 503})

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Require at least one email endpoint the operator confirmed is safe to burst.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: Skip reason, or None.
        '''
        if not auth.email_endpoints:
            return "no 'email_endpoints' listed in the authorization"
        if not any(t.confirmed_no_real_delivery for t in auth.email_endpoints):
            return ("no listed email endpoint has confirmed_no_real_delivery: true "
                    "(this check never sends to a real recipient)")
        return None

    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Burst each confirmed-safe, in-scope endpoint and flag any that never throttle.
        Parameters:
            ctx (ActiveContext): Shared context.
        Returns:
            ActiveCheckResult: Findings for endpoints showing no throttling.
        '''
        started = datetime.now(UTC)
        findings: list[Finding] = []
        errors: list[CollectionError] = []
        start_count = ctx.check_count(self.check_id)
        for target in ctx.auth.email_endpoints:
            host = urlsplit(target.url).hostname
            if not target.confirmed_no_real_delivery:
                continue   # never burst an endpoint the operator has not confirmed is safe
            if not ctx.auth.scope.allows(host):
                continue
            statuses, hit_budget = await self._burst(ctx, target, errors)
            if not statuses:
                continue
            throttled = any(s in self.THROTTLE_CODES for s in statuses)
            accepted = sum(1 for s in statuses if 200 <= s < 400)
            full_burst = len(statuses) == target.burst and not hit_budget
            if full_burst and not throttled and accepted == len(statuses):
                findings.append(self._finding(
                    "active.no_rate_limit", redact_url(target.url),
                    title="Email/notification endpoint accepted a full burst with no throttling",
                    description=f"A burst of {len(statuses)} test-marked requests was accepted without any "
                                "throttling response (429/503). An endpoint that sends email or notifications "
                                "without rate limiting can be abused to flood a recipient or run up cost.",
                    severity=S.MEDIUM, confidence=C.MEDIUM,
                    evidence=[f"{len(statuses)} requests, statuses {sorted(set(statuses))}, none throttled",
                              "payload: operator-provided test marker; endpoint confirmed non-delivering"],
                    source="bounded test burst against an operator-confirmed non-delivering endpoint",
                    recommendation="Add per-IP/per-account rate limiting and abuse controls to this endpoint."))
        requests = ctx.check_count(self.check_id) - start_count
        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return self._result("email endpoints", started, status=status, findings=findings, requests=requests,
                            errors=errors)

    async def _burst(self, ctx: ActiveContext, target, errors: list[CollectionError]) -> tuple[list[int], bool]:
        '''
        Send the capped, paced burst for one endpoint.
        Parameters:
            ctx (ActiveContext): Shared context (enforces the rate and budget).
            target (EmailEndpointTarget): The endpoint.
            errors (list[CollectionError]): Error accumulator.
        Returns:
            tuple[list[int], bool]: Response status codes, and whether the budget stopped the burst early.
        '''
        payload = (target.test_payload or '{"siterecon_test": true}').encode("utf-8")
        headers = {"Content-Type": "application/json", "X-SiteRecon-Test": "rate-limit-probe"}
        statuses: list[int] = []
        for _ in range(target.burst):
            try:
                resp = await ctx.request(self.check_id, target.method, target.url, content=payload,
                                         headers=headers, note="rate-limit burst (test payload)")
            except BudgetExceeded as exc:
                errors.append(CollectionError(module=self.check_id, target=target.url,
                                              error_type="budget_exceeded", message=str(exc)))
                return statuses, True
            if resp is not None:
                statuses.append(resp.status_code)
        return statuses, False


class TlsProtocolEnumCheck(ActiveCheck):
    '''
    Enumerates which TLS protocol versions a host still accepts, for hosts with the extra per-host opt-in.
    '''

    check_id: ClassVar[str] = "tls_protocol_enum"
    description: ClassVar[str] = ("Attempts a handshake at each TLS version against hosts carrying the per-host "
                                  "tls_authorized opt-in, and flags legacy (TLS 1.0/1.1) acceptance.")
    VERSIONS: ClassVar[tuple[tuple[str, ssl.TLSVersion], ...]] = (
        ("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    )
    LEGACY: ClassVar[frozenset[str]] = frozenset({"TLSv1.0", "TLSv1.1"})

    def __init__(self, timeout: float = 10.0) -> None:
        '''
        Create the check.
        Parameters:
            timeout (float): Per-handshake timeout in seconds.
        '''
        self.timeout = timeout

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Require at least one host with the per-host tls_authorized opt-in.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: Skip reason, or None.
        '''
        if not any(auth.scope.tls_authorized(h) for h in auth.scope.normalized_hosts()):
            return "no host carries the per-host tls_authorized opt-in required for TLS enumeration"
        return None

    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Enumerate accepted TLS versions and ciphers for each tls-authorized host.
        Parameters:
            ctx (ActiveContext): Shared context (budget/rate also cover handshakes).
        Returns:
            ActiveCheckResult: Findings for hosts accepting legacy TLS.
        '''
        started = datetime.now(UTC)
        findings: list[Finding] = []
        errors: list[CollectionError] = []
        start_count = ctx.check_count(self.check_id)
        hosts = sorted(h for h in ctx.auth.scope.normalized_hosts() if ctx.auth.scope.tls_authorized(h))
        for host in hosts:
            # Record the outcome for EVERY version in order, so the evidence shows what was offered
            outcomes: dict[str, str] = {}
            accepted: dict[str, str] = {}
            for name, version in self.VERSIONS:
                ssl_ctx = self._client_context(version)
                if ssl_ctx is None:
                    outcomes[name] = "not attempted (this OpenSSL build cannot offer it)"
                    continue
                try:
                    await ctx.reserve_handshake(self.check_id)
                except BudgetExceeded as exc:
                    errors.append(CollectionError(module=self.check_id, target=host,
                                                  error_type="budget_exceeded", message=str(exc)))
                    outcomes[name] = "not attempted (request budget exhausted)"
                    break
                cipher = await self._handshake(host, ssl_ctx)
                outcomes[name] = f"accepted (cipher {cipher})" if cipher is not None else "offered, rejected"
                if cipher is not None:
                    accepted[name] = cipher
                ctx.log_probe(self.check_id, "TLS", f"{host}:443", note=f"{name}: {outcomes[name]}")

            evidence = [f"{name}: {outcomes[name]}" for name, _ in self.VERSIONS]
            legacy = sorted(v for v in accepted if v in self.LEGACY)
            if legacy:
                findings.append(self._finding(
                    "active.legacy_tls_accepted", f"{host}:443",
                    title="Legacy TLS version accepted",
                    description=f"The server completed a handshake using {', '.join(legacy)}, which is deprecated "
                                "(RFC 8996). Legacy TLS is vulnerable to known downgrade and protocol attacks. "
                                "The evidence lists every version offered and its outcome.",
                    severity=S.MEDIUM, confidence=C.HIGH, evidence=evidence,
                    source="per-version TLS handshakes (offered each version individually)"))
            elif accepted:
                findings.append(self._finding(
                    "active.tls_versions", f"{host}:443",
                    title="TLS versions accepted",
                    description="Enumeration of TLS versions (informational): every version was offered "
                                "individually; the evidence shows which were accepted and which were rejected.",
                    severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=evidence,
                    source="per-version TLS handshakes (offered each version individually)"))
        requests = ctx.check_count(self.check_id) - start_count
        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return self._result("TLS hosts", started, status=status, findings=findings, requests=requests, errors=errors)

    @staticmethod
    def _client_context(version: ssl.TLSVersion) -> ssl.SSLContext | None:
        '''
        Build an SSL context pinned to exactly one TLS version, or None if this OpenSSL build can't offer it.

        Checked before any network request so an unavailable version costs neither a connection nor a
        slot in the engagement request budget.
        Parameters:
            version (ssl.TLSVersion): The exact version to offer.
        Returns:
            ssl.SSLContext | None: The pinned context, or None if the build cannot offer that version.
        '''
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE   # posture/version enumeration, not cert validation
        try:
            ssl_ctx.minimum_version = version
            ssl_ctx.maximum_version = version
        except ValueError:
            return None
        if version <= ssl.TLSVersion.TLSv1_1:
            try:
                ssl_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # allow legacy ciphers so the attempt is meaningful
            except ssl.SSLError:
                return None
        return ssl_ctx

    async def _handshake(self, host: str, ssl_ctx: ssl.SSLContext) -> str | None:
        '''
        Attempt a handshake with a version-pinned context; return the negotiated cipher or None.

        The host is resolved and the connection is made only to a publicly routable address (the same
        SSRF guard the passive TLS module applies), with SNI set to the authorized hostname.
        Parameters:
            host (str): Hostname (port 443).
            ssl_ctx (ssl.SSLContext): A context pinned to the single version being probed.
        Returns:
            str | None: Negotiated cipher suite name, or None if the handshake was refused/blocked.
        '''
        from recon.utils import is_public_ip, system_resolve

        try:
            addresses = await system_resolve(host, 443)
        except OSError:
            return None
        vetted = next((a for a in addresses if is_public_ip(a)), None)
        if vetted is None:
            return None                      # refuse private/loopback/metadata addresses
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(vetted, 443, ssl=ssl_ctx, server_hostname=host), timeout=self.timeout)
        except (ssl.SSLError, OSError, TimeoutError):
            return None
        try:
            tls_obj = writer.get_extra_info("ssl_object")
            cipher = tls_obj.cipher() if tls_obj else None
            return cipher[0] if cipher else "unknown"
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (OSError, ssl.SSLError, TimeoutError):
                pass


class PortScanCheck(ActiveCheck):
    '''
    Checks which operator-listed TCP ports accept connections on in-scope hosts.

    A bounded TCP connect scan: one connection attempt per operator-listed port, classified open/closed/
    filtered. Only ports the operator named (explicitly or via a profile) are probed, and no banner is
    grabbed — service names come from a static well-known-port map, not from the response — so this is a
    reachability inventory, not aggressive fingerprinting.
    '''

    check_id: ClassVar[str] = "port_scan"
    description: ClassVar[str] = ("Attempts one bounded TCP connect per operator-listed port on each in-scope "
                                  "host, recording open/closed/filtered with conservative service identification.")

    WELL_KNOWN: ClassVar[dict[int, str]] = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
        111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 465: "smtps",
        587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
        3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 5984: "couchdb", 6379: "redis",
        8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}
    # Ports fronting services that are usually not meant to be internet-facing (databases, admin, sharing).
    SENSITIVE: ClassVar[dict[int, str]] = {
        22: "SSH", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
        2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}

    def __init__(self, timeout: float = 3.0) -> None:
        '''
        Create the check.
        Parameters:
            timeout (float): Per-connection timeout in seconds.
        '''
        self.timeout = timeout

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Require at least one listed port-scan target whose host is in scope.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: Skip reason, or None.
        '''
        if not auth.port_scan_targets:
            return "no 'port_scan_targets' listed in the authorization"
        if not any(auth.scope.allows(t.host) for t in auth.port_scan_targets):
            return "none of the listed port_scan_targets have a host in scope.hosts"
        return None

    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Connect-scan each in-scope target's authorized ports and flag the ones that are open.
        Parameters:
            ctx (ActiveContext): Shared context (budget/rate also cover each connection).
        Returns:
            ActiveCheckResult: Findings for hosts with open ports.
        '''
        started = datetime.now(UTC)
        findings: list[Finding] = []
        errors: list[CollectionError] = []
        start_count = ctx.check_count(self.check_id)
        for target in ctx.auth.port_scan_targets:
            if not ctx.auth.scope.allows(target.host):
                continue
            open_ports: dict[int, str] = {}
            for port in target.resolved_ports():
                try:
                    await ctx.reserve_handshake(self.check_id)
                except BudgetExceeded as exc:
                    errors.append(CollectionError(module=self.check_id, target=target.host,
                                                  error_type="budget_exceeded", message=str(exc)))
                    break
                state = await self._probe_port(target.host, port)
                ctx.log_probe(self.check_id, "TCP", f"{target.host}:{port}", note=state)
                if state == "open":
                    open_ports[port] = self.WELL_KNOWN.get(port, "unknown")
            if open_ports:
                findings.extend(self._port_findings(target.host, open_ports))
        requests = ctx.check_count(self.check_id) - start_count
        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return self._result("port-scan hosts", started, status=status, findings=findings, requests=requests,
                            errors=errors)

    async def _probe_port(self, host: str, port: int) -> str:
        '''
        Resolve a host to a public address and connect-probe one port.

        Connections are made only to a publicly routable address (the same SSRF guard the passive modules
        apply); a host that resolves only to private/loopback/metadata space is reported as 'blocked'.
        Parameters:
            host (str): Hostname to probe.
            port (int): TCP port.
        Returns:
            str: 'open', 'closed', 'filtered' or 'blocked'.
        '''
        from recon.utils import is_public_ip, system_resolve

        try:
            addresses = await system_resolve(host, port)
        except OSError:
            return "filtered"
        vetted = next((a for a in addresses if is_public_ip(a)), None)
        if vetted is None:
            return "blocked"
        return await self._connect(vetted, port)

    async def _connect(self, ip: str, port: int) -> str:
        '''
        Open a TCP connection to a vetted address and classify the outcome.
        Parameters:
            ip (str): A publicly routable IP address.
            port (int): TCP port.
        Returns:
            str: 'open' (connected), 'closed' (refused) or 'filtered' (timeout/unreachable).
        '''
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
        except ConnectionRefusedError:
            return "closed"
        except (TimeoutError, OSError):
            return "filtered"
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except (OSError, TimeoutError):
            pass
        return "open"

    def _port_findings(self, host: str, open_ports: dict[int, str]) -> list[Finding]:
        '''
        Build the open-ports inventory finding and, if any sensitive service is reachable, a flagged one.
        Parameters:
            host (str): The scanned host.
            open_ports (dict[int, str]): Open port to service name.
        Returns:
            list[Finding]: One or two findings.
        '''
        listing = ", ".join(f"{p}/{svc}" for p, svc in sorted(open_ports.items()))
        out: list[Finding] = [self._finding(
            "active.open_ports", host, title=f"Open TCP ports on {host}",
            description="A bounded TCP connect scan found these ports accepting connections. Only "
                        "operator-listed ports were probed and no banners were grabbed; confirm each is "
                        "intended to be reachable from the internet.",
            severity=S.INFORMATIONAL, confidence=C.HIGH, evidence=[f"open: {listing}"],
            source="TCP connect scan (operator-listed ports)")]
        sensitive = {p: self.SENSITIVE[p] for p in open_ports if p in self.SENSITIVE}
        if sensitive:
            names = ", ".join(f"{p} ({n})" for p, n in sorted(sensitive.items()))
            out.append(self._finding(
                "active.sensitive_port_exposed", host, title="Sensitive service port reachable from the internet",
                description="These ports front services that are usually not meant to be internet-facing "
                            "(databases, remote administration, file sharing). Reachability is not proof of a "
                            "vulnerability, but such services normally belong behind a firewall/VPN or an IP "
                            "allow-list.",
                severity=S.MEDIUM, confidence=C.MEDIUM, evidence=[f"reachable: {names}"],
                source="TCP connect scan (operator-listed ports)"))
        return out


class TracerouteCheck(ActiveCheck):
    '''
    Discovers the network path toward operator-listed in-scope hosts using the system traceroute utility.

    The result is a point-in-time path observation (hops may not respond, and the path can change), not
    proof of the complete physical routing topology. The utility is run with a bounded hop count toward a
    vetted public address only; if no traceroute binary is available the check records an error and
    continues.
    '''

    check_id: ClassVar[str] = "traceroute"
    description: ClassVar[str] = ("Runs a bounded traceroute toward each in-scope host and records the network "
                                  "path (hops and round-trip times).")

    def __init__(self, timeout: float = 5.0) -> None:
        '''
        Create the check.
        Parameters:
            timeout (float): Per-hop wait in seconds (also bounds the overall run).
        '''
        self.timeout = timeout

    def prerequisites(self, auth: AuthorizationFile) -> str | None:
        '''
        Require at least one listed traceroute target whose host is in scope.
        Parameters:
            auth (AuthorizationFile): The authorization.
        Returns:
            str | None: Skip reason, or None.
        '''
        if not auth.traceroute_targets:
            return "no 'traceroute_targets' listed in the authorization"
        if not any(auth.scope.allows(t.host) for t in auth.traceroute_targets):
            return "none of the listed traceroute_targets have a host in scope.hosts"
        return None

    async def run(self, ctx: ActiveContext) -> ActiveCheckResult:
        '''
        Trace the path to each in-scope target and record it as one finding per reachable target.
        Parameters:
            ctx (ActiveContext): Shared context (each traceroute counts as one probe against the budget).
        Returns:
            ActiveCheckResult: One informational path finding per target that produced hops.
        '''
        started = datetime.now(UTC)
        findings: list[Finding] = []
        errors: list[CollectionError] = []
        start_count = ctx.check_count(self.check_id)
        for target in ctx.auth.traceroute_targets:
            if not ctx.auth.scope.allows(target.host):
                continue
            ip = await self._vetted_ip(target.host)
            if ip is None:
                errors.append(CollectionError(module=self.check_id, target=target.host,
                                              error_type="blocked_address",
                                              message="host did not resolve to a public address"))
                continue
            try:
                await ctx.reserve_handshake(self.check_id)   # one probe per traceroute operation
            except BudgetExceeded as exc:
                errors.append(CollectionError(module=self.check_id, target=target.host,
                                              error_type="budget_exceeded", message=str(exc)))
                break
            hops = await self._trace(ip, target.max_hops)
            ctx.log_probe(self.check_id, "TRACE", f"{target.host} ({ip})",
                          note=f"{len(hops)} hop(s)" if hops else "no path / unavailable")
            if hops is None:
                errors.append(CollectionError(module=self.check_id, target=target.host,
                                              error_type="traceroute_unavailable",
                                              message="traceroute utility not available or failed"))
                continue
            if hops:
                findings.append(self._finding(
                    "active.network_path", target.host, title=f"Network path to {target.host}",
                    description="The route packets took toward this host, as reported by the system traceroute "
                                "utility. This is a point-in-time path observation — hops may not respond and the "
                                "path can change — not proof of the complete physical topology.",
                    severity=S.INFORMATIONAL, confidence=C.MEDIUM, evidence=hops[:40],
                    source=f"system traceroute toward {ip} (max {target.max_hops} hops)"))
        requests = ctx.check_count(self.check_id) - start_count
        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return self._result("traceroute hosts", started, status=status, findings=findings, requests=requests,
                            errors=errors)

    @staticmethod
    async def _vetted_ip(host: str) -> str | None:
        '''
        Resolve a host and return its first publicly routable address, or None.
        Parameters:
            host (str): Hostname to resolve.
        Returns:
            str | None: A public IP, or None if it resolves only to private/blocked space or not at all.
        '''
        from recon.utils import is_public_ip, system_resolve

        try:
            addresses = await system_resolve(host, 0)
        except OSError:
            return None
        return next((a for a in addresses if is_public_ip(a)), None)

    async def _trace(self, ip: str, max_hops: int) -> list[str] | None:
        '''
        Run the system traceroute toward a vetted IP and return its hop lines, or None if it was unavailable.

        The address is passed as an argument (never a shell string), and only to a vetted public IP, so no
        untrusted input reaches a shell and no private destination is traced.
        Parameters:
            ip (str): A vetted public IP address.
            max_hops (int): Maximum hops.
        Returns:
            list[str] | None: Per-hop lines (header dropped), or None if the binary is missing or it failed.
        '''
        import sys

        if sys.platform.startswith("win"):
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(self.timeout * 1000)), ip]
        else:
            cmd = ["traceroute", "-n", "-q", "1", "-m", str(max_hops), "-w", str(max(1, int(self.timeout))), ip]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        except (FileNotFoundError, OSError):
            return None
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout * max_hops + 10)
        except TimeoutError:
            proc.kill()
            return None
        if proc.returncode not in (0, None):
            return None
        lines = out.decode("utf-8", "replace").splitlines()
        return [ln.strip() for ln in lines[1:] if ln.strip()][:max_hops]   # drop the "traceroute to …" header


# Deprecated import alias: the Supabase row-level-security check was reframed as the backend-agnostic
# BackendReadAccessCheck. Kept so `from recon.active.checks import SupabaseRlsCheck` keeps importing.
SupabaseRlsCheck = BackendReadAccessCheck


REGISTRY: dict[str, type[ActiveCheck]] = {
    BackendReadAccessCheck.check_id: BackendReadAccessCheck,
    FunctionUrlReachabilityCheck.check_id: FunctionUrlReachabilityCheck,
    ClientIpHeaderTrustCheck.check_id: ClientIpHeaderTrustCheck,
    EmailEndpointRateLimitCheck.check_id: EmailEndpointRateLimitCheck,
    TlsProtocolEnumCheck.check_id: TlsProtocolEnumCheck,
    PortScanCheck.check_id: PortScanCheck,
    TracerouteCheck.check_id: TracerouteCheck,
}


def build_check(check_id: str) -> ActiveCheck:
    '''
    Instantiate a registered check by id.
    Parameters:
        check_id (str): The check identifier.
    Returns:
        ActiveCheck: A new instance.
    Raises:
        KeyError: If the id is not registered.
    '''
    return REGISTRY[check_id]()
