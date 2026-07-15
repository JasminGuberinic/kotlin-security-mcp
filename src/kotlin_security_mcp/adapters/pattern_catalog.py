"""An in-memory catalog of secure patterns, plus the matching that finds them.

The recipes below are distilled from the kotlin-security-scanner rules: for each
class of mistake the scanner *detects*, this catalog offers the secure shape to
write instead. Keeping them here (an adapter) means the domain and use case stay
free of any hard-coded content.
"""

from __future__ import annotations

from kotlin_security_mcp.domain.patterns import SecurePattern

# The curated recipes. Each keyword is lowercase; the matcher compares them
# against the agent's free-text task, so pick words an agent would actually use.
_PATTERNS: tuple[SecurePattern, ...] = (
    SecurePattern(
        framework="vertx",
        task="Create a secure session cookie",
        keywords=("cookie", "session", "samesite", "httponly"),
        insecure_example=(
            'val cookie = Cookie.cookie("session", token)\n'
            "response.addCookie(cookie)"
        ),
        secure_example=(
            'val cookie = Cookie.cookie("session", token)\n'
            "    .setSecure(true)      // only sent over HTTPS\n"
            "    .setHttpOnly(true)    // hidden from JavaScript\n"
            "    .setSameSite(CookieSameSite.STRICT)\n"
            "response.addCookie(cookie)"
        ),
        explanation=(
            "Secure + HttpOnly + SameSite keep the cookie off plain HTTP, out of "
            "reach of XSS/JavaScript, and protected from CSRF."
        ),
        cwe="CWE-614",
    ),
    SecurePattern(
        framework="spring-webflux",
        task="Read the current authenticated user in reactive code",
        keywords=("current", "user", "authentication", "reactive", "securitycontext"),
        insecure_example=(
            "// Empty on reactive threads — the ThreadLocal is not populated.\n"
            "val auth = SecurityContextHolder.getContext().authentication"
        ),
        secure_example=(
            "fun currentUser(): Mono<Authentication> =\n"
            "    ReactiveSecurityContextHolder.getContext()\n"
            "        .map { it.authentication }"
        ),
        explanation=(
            "Reactive requests do not run on the thread that holds the "
            "SecurityContextHolder. ReactiveSecurityContextHolder reads the "
            "context from the Reactor Context instead."
        ),
        cwe="CWE-863",
    ),
    SecurePattern(
        framework="spring-webflux",
        task="Configure WebClient TLS safely",
        keywords=("webclient", "ssl", "tls", "certificate", "trust"),
        insecure_example=(
            "val httpClient = HttpClient.create().secure {\n"
            "    it.sslContext(SslContextBuilder.forClient()\n"
            "        .trustManager(InsecureTrustManagerFactory.INSTANCE).build())\n"
            "}"
        ),
        secure_example=(
            "// Use the JVM default trust store; never trust all certificates.\n"
            'val webClient = WebClient.create("https://api.example.com")'
        ),
        explanation=(
            "InsecureTrustManagerFactory disables certificate validation and "
            "enables man-in-the-middle attacks. Rely on the default trust "
            "manager or a pinned CA."
        ),
        cwe="CWE-295",
    ),
    SecurePattern(
        framework="any",
        task="Create an SSLContext with a safe protocol",
        keywords=("sslcontext", "protocol", "tls", "ssl"),
        insecure_example='val ctx = SSLContext.getInstance("SSL")   // also TLSv1/TLSv1.1',
        secure_example='val ctx = SSLContext.getInstance("TLSv1.3") // or "TLSv1.2"',
        explanation="SSL and TLS 1.0/1.1 are broken; require TLS 1.2 or newer.",
        cwe="CWE-327",
    ),
    SecurePattern(
        framework="any",
        task="Store a secret or signing key",
        keywords=("secret", "key", "jwt", "password", "credential", "token"),
        insecure_example='val secret = "my-super-secret-signing-key"',
        secure_example=(
            'val secret = System.getenv("JWT_SIGNING_KEY")\n'
            '    ?: error("JWT_SIGNING_KEY is not set")'
        ),
        explanation=(
            "Secrets in source code leak into version control and build "
            "artifacts. Load them from the environment or a secret manager."
        ),
        cwe="CWE-798",
    ),
    SecurePattern(
        framework="any",
        task="Generate a random token securely",
        keywords=("random", "token", "securerandom", "nonce", "seed"),
        insecure_example="val rng = SecureRandom(byteArrayOf(1, 2, 3, 4)) // fixed seed",
        secure_example=(
            "val rng = SecureRandom() // seeded from the OS CSPRNG\n"
            "val token = ByteArray(32).also { rng.nextBytes(it) }"
        ),
        explanation=(
            "A fixed seed makes the output predictable. The no-arg constructor "
            "draws entropy from the operating system."
        ),
        cwe="CWE-330",
    ),
    SecurePattern(
        framework="ktor",
        task="Configure CORS in Ktor",
        keywords=("cors", "origin", "anyhost", "cross-origin"),
        insecure_example="install(CORS) { anyHost() }",
        secure_example=(
            "install(CORS) {\n"
            '    allowHost("app.example.com", schemes = listOf("https"))\n'
            "    allowCredentials = true\n"
            "}"
        ),
        explanation=(
            "anyHost() (especially with credentials) exposes authenticated "
            "endpoints to every origin. Allow only the hosts you trust."
        ),
        cwe="CWE-942",
    ),
)


class InMemorySecurePatternCatalog:
    """A SecurePatternCatalog backed by the curated `_PATTERNS` list.

    It satisfies the SecurePatternCatalog port structurally via its `find`
    method. Matching is deliberately simple and explainable: filter by
    framework, then rank by how many keywords the task mentions.
    """

    # How many suggestions we return at most, best first.
    _MAX_RESULTS = 3

    def __init__(self, patterns: tuple[SecurePattern, ...] = _PATTERNS) -> None:
        # Allow injecting a custom list (tests do this); default to the catalog.
        self._patterns = patterns

    def find(self, framework: str | None, task: str) -> tuple[SecurePattern, ...]:
        """Return up to `_MAX_RESULTS` patterns matching the task, best first."""
        task_text = task.lower()
        wanted_framework = self._normalize_framework(framework)

        scored = [
            (self._score(pattern, task_text), pattern)
            for pattern in self._patterns
            if self._framework_matches(pattern, wanted_framework)
        ]
        # Keep only real matches (at least one keyword hit).
        hits = [(score, pattern) for score, pattern in scored if score > 0]
        # Highest score first; Python's sort is stable so catalog order breaks ties.
        hits.sort(key=lambda pair: pair[0], reverse=True)
        return tuple(pattern for _, pattern in hits[: self._MAX_RESULTS])

    def _normalize_framework(self, framework: str | None) -> str | None:
        """Lowercase the framework, treating blank input as "no filter"."""
        if framework is None or not framework.strip():
            return None
        return framework.strip().lower()

    def _framework_matches(self, pattern: SecurePattern, wanted: str | None) -> bool:
        """A pattern is eligible when no framework was asked for, when it is
        framework-agnostic ("any"), or when the names overlap either way
        (so "spring" matches "spring-webflux" and vice versa)."""
        if wanted is None or pattern.framework == "any":
            return True
        return wanted in pattern.framework or pattern.framework in wanted

    def _score(self, pattern: SecurePattern, task_text: str) -> int:
        """Count how many of the pattern's keywords appear in the task text."""
        return sum(1 for keyword in pattern.keywords if keyword in task_text)
