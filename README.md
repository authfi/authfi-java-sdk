# AuthFI Java SDK

Official Java SDK for [AuthFI](https://authfi.io) — the identity control plane.
**One artifact, one dep, three usage modes** (customer web app, customer service, AI agent process).

```xml
<dependency>
    <groupId>io.authfi</groupId>
    <artifactId>authfi-sdk</artifactId>
    <version>0.3.1</version>
</dependency>
```

## TL;DR — Spring Boot users

AuthFI is an OIDC provider. Use Spring's existing OAuth2 Resource Server starter and point it at your tenant. Everything you already know — `@PreAuthorize`, `@AuthenticationPrincipal Jwt` — works verbatim.

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://acme.authfi.io
```

```java
@RestController
class UsersController {

    @GetMapping("/api/users")
    @PreAuthorize("hasAuthority('read:users')")    // ← stock Spring Security
    List<User> list() { ... }

    @GetMapping("/api/me")
    User me(@AuthenticationPrincipal Jwt jwt) {    // ← stock Spring Security
        return userService.find(jwt.getSubject());
    }
}
```

Add the AuthFI bean only if you want to call the management API (users, orgs, agents, audit logs):

```yaml
authfi:
  tenant: acme
  client-id: ${AUTHFI_CLIENT_ID}
  client-secret: ${AUTHFI_CLIENT_SECRET}
```

```java
@Autowired AuthFI authfi;
authfi.users().list();
authfi.agents().register(userJwt, "Triage bot", "...", AgentType.DELEGATED);
```

The starter:

- Auto-registers an `AuthFIJwtAuthenticationConverter` so `permissions[]` claim values land as bare authorities (`hasAuthority('read:users')` not `'SCOPE_read:users'`) and `roles[]` get a `ROLE_` prefix (`hasRole('admin')`).
- Auto-scans every `@PreAuthorize` annotation at boot, extracts permission literals, and syncs the catalog to the AuthFI console — devs never call `permissions().register(...)` manually. Disable with `authfi.permission-sync.enabled=false`.

## Three usage modes

```java
// 1. Customer web app — API key (simplest)
AuthFI authfi = AuthFI.client()
    .tenant("acme")
    .apiKey("sk_live_...")
    .build();

// 2. Customer service — OAuth2 client_credentials
AuthFI authfi = AuthFI.service()
    .tenant("acme")
    .clientId("FIC-abc123")
    .clientSecret("FIS-xyz...")
    .build();

// 3. AI agent process — AuthFI Agent Profile
AuthFI agent = AuthFI.agent().fromEnv().build();
// reads AUTHFI_TENANT / AUTHFI_AGENT_ID
//     + AUTHFI_AGENT_PRIVATE_KEY_FILE (or _PRIVATE_KEY) and AUTHFI_AGENT_KEY_ID
//     legacy: AUTHFI_AGENT_SECRET
```

## Agentic — the AuthFI Agent Profile

Three phases. Owner registers, agent runs, gated actions wait for human approval.

### How the agent authenticates

**The agent holds its own Ed25519 keypair and proves possession by signing a short assertion**
(RFC 7523 §2.2 `private_key_jwt`). The private half never leaves the process and is never sent to
AuthFI.

This is the only method the platform advertises — its discovery document
(`/.well-known/agent-configuration`) lists
`"token_endpoint_auth_methods_supported": ["private_key_jwt"]` and nothing else. **Registering an
agent with a public JWK issues no client secret at all**, and the server picks the credential from
the agent's stored record rather than from the request, so a key-registered agent cannot fall back
to a secret. A downgrade no caller can ask for is a downgrade no attacker can force.

Generate a key:

```sh
openssl genpkey -algorithm ed25519 -out agent.key
openssl pkey -in agent.key -pubout -outform DER | tail -c 32 | basenc --base64url | tr -d '='
# register that 32-byte value as the JWK "x", with a kid you choose
```

### Phase 1 — owner registers the agent (one-time)

Runs inside the customer's web app, with the logged-in user's Bearer token:

```java
AgentCredentials creds = authfi.agents().register(
    userBearerToken,
    "Inbox triage bot",
    "Summarizes new mail every 5min",
    AgentType.DELEGATED);
// creds.agentId() — keep it. clientSecret() is empty for a key-registered agent.
```

### Phase 2 — agent process bootstraps and runs

The agent process embeds the SDK with its own identity. The token cache + auto-refresh is invisible to caller code:

```java
// Key-based (what the platform expects)
AuthFI agent = AuthFI.agent()
    .tenant("acme")
    .agentId("agt_...")
    .agentPrivateKey(Files.readString(Path.of("/run/secrets/agent.key")))
    .agentKeyId("key-1")
    .build();

// or entirely from the environment
AuthFI fromEnv = AuthFI.agent().fromEnv().build();

// Capability check — no JWT decoding
if (!agent.agentAuth().can("summarize_email")) return;

// Normal work, no HIL needed
Summary s = llm.summarize(email);
```

### Phase 3 — gated action, one line

For HIL-required actions, `guard` wraps capability check → approval request → bounded poll with exponential backoff → execution. No `while (status.isPending())` loop in your code:

```java
agent.agentAuth().guard("send_email_external", Map.of("to", boss), () -> {
    smtp.send(boss, "Daily summary", body);
    return null;
});
// Throws ApprovalDeniedException on deny / expire / timeout — pick one switch.
```

The request is signed with the agent's key and sent to the approval endpoint the deployment advertises;
no client secret is involved. Or do it manually with the sealed `Approval` result:

```java
ApprovalRequest req = agent.agentAuth().requestApproval("send_external", Map.of(...));
Approval decision = agent.agentAuth().awaitDecision(req.approvalId(), Duration.ofMinutes(5));

if (decision instanceof Approval.Approved a) { ... }
else if (decision instanceof Approval.Denied d) { ... }
else if (decision instanceof Approval.Expired e) { ... }
else if (decision instanceof Approval.TimedOut t) { ... }
```

### User portal — managing the agents one has authorized

In the user-facing web app:

```java
authfi.myAgents().list(userJwt);
authfi.myAgents().approvals(userJwt);
authfi.myAgents().resolve(userJwt, approvalId, /* approved */ true);
authfi.myAgents().revoke(userJwt, agentId);
authfi.myAgents().activity(userJwt, agentId);
```

## Verifying tokens in your API

```java
TokenVerifier verifier = authfi.verifier("api_orders");   // your API's audience
AuthFIClaims claims = verifier.verifyHeader(request.getHeader("Authorization"));
```

The verifier accepts only access tokens (`typ` `at+jwt`) signed with EdDSA, ES256, PS256 or RS256 by a key
the issuer publishes, whose `iss` is your tenant, whose `aud` names your API, and which has not expired. A
user's token, an agent's token and a token an agent holds for a person all verify the same way. An ID token,
a token for another API, or a token with no audience is refused with a `token_*` code
(`AuthFIException.getCode()`). The audience is required: a verifier without one cannot be built.

Configuration objects print identifiers only; keys, secrets and tokens never appear in `toString`, logs or
exception messages.

## Migration from incumbents — one URL change

| If you currently use | Change |
|---|---|
| Okta + Spring | `issuer-uri: https://acme.okta.com` → `https://acme.authfi.io` |
| Auth0 + Spring | `issuer-uri: https://acme.auth0.com/` → `https://acme.authfi.io` |
| Cognito + Spring | same |

Your `@PreAuthorize` annotations don't change.

## Full module list

| Module                   | What it wraps                                                   | Auth                     |
|--------------------------|-----------------------------------------------------------------|--------------------------|
| `authfi.verifier(aud...)`| Access-token verification: EdDSA, ES256, PS256, RS256; iss, aud, exp, typ | n/a (verification only)  |
| `authfi.users()`         | User CRUD, role/group assignment, block/unblock                 | API key / service        |
| `authfi.orgs()`          | Org CRUD, members, SSO config, branding                          | API key / service        |
| `authfi.permissions()`   | Permission catalog sync, role-permission binding                 | API key / service        |
| `authfi.me()`            | `/me`, `/userinfo`, change own password, security-score          | end-user JWT             |
| `authfi.sessions()`      | List/revoke own sessions; admin per-user views                   | mixed                    |
| `authfi.mfa()`           | TOTP enroll/verify/list/unenroll                                  | end-user JWT             |
| `authfi.auditLogs()`     | Audit log search (limit/offset/since)                            | API key / service        |
| `authfi.tokenIntrospection()` | RFC 7662 introspect + RFC 7009 revoke                       | none (public)            |
| `authfi.discovery()`     | `.well-known/{openid-configuration, jwks, smart-configuration, agent-configuration}` | none |
| `authfi.connect()`       | Cloud credentials — GCP, AWS, Azure, OCI                         | API key / service        |
| `authfi.agents()`        | Owner-driven agent registration (Phase 1)                         | end-user JWT             |
| `authfi.myAgents()`      | End-user portal for managing one's agents (Phase 4)               | end-user JWT             |
| `authfi.agentAuth()`     | AuthFI Agent Profile — token, request-approval, guard, can (Phase 2 & 3)           | agent_credentials        |
| `authfi.aiAgentRegistry()` | Admin: AI agent identity registry CRUD                          | API key / service        |
| `authfi.aiRuns()`        | Admin: AI run lifecycle (+ taint / restore / revoke)              | API key / service        |
| `authfi.mcpTools()`      | Admin: MCP tool catalog                                           | API key / service        |
| `authfi.mcpCalls()`      | Admin: MCP call audit                                             | API key / service        |

## OAuth2 token exchange (RFC 8693 on-behalf-of)

```java
String scopedToken = authfi.onBehalfOf(userAccessToken).token("read:patients");
```

## Running tests

```bash
mvn test
```

46 unit tests — all passing.

## License

Apache-2.0
