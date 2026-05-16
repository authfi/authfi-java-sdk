# AuthFI Java SDK

Official Java SDK for [AuthFI](https://authfi.app) — the identity control plane.
**One artifact, one dep, three usage modes** (customer web app, customer service, AI agent process).

```xml
<dependency>
    <groupId>com.quefly.authfi</groupId>
    <artifactId>authfi-sdk</artifactId>
    <version>0.2.0</version>
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
          issuer-uri: https://acme.authfi.app
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

// 3. AI agent process — AuthFI Agent Protocol (AAP)
AuthFI agent = AuthFI.agent().fromEnv().build();
// reads AUTHFI_TENANT / AUTHFI_AGENT_ID / AUTHFI_AGENT_SECRET
```

## Agentic — the AuthFI Agent Protocol (AAP)

Three phases. Owner registers, agent runs, gated actions wait for human approval.

### Phase 1 — owner registers the agent (one-time)

Runs inside the customer's web app, with the logged-in user's Bearer token:

```java
AgentCredentials creds = authfi.agents().register(
    userBearerToken,
    "Inbox triage bot",
    "Summarizes new mail every 5min",
    AgentType.DELEGATED);
// creds.agentId(), creds.clientSecret() — shown ONCE, persist securely
```

### Phase 2 — agent process bootstraps and runs

The agent process embeds the SDK with its own identity. The token cache + auto-refresh is invisible to caller code:

```java
AuthFI agent = AuthFI.agent().fromEnv().build();

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

Or do it manually with the sealed `Approval` result:

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

## Migration from incumbents — one URL change

| If you currently use | Change |
|---|---|
| Okta + Spring | `issuer-uri: https://acme.okta.com` → `https://acme.authfi.app` |
| Auth0 + Spring | `issuer-uri: https://acme.auth0.com/` → `https://acme.authfi.app` |
| Cognito + Spring | same |

Your `@PreAuthorize` annotations don't change.

## Full module list

| Module                   | What it wraps                                                   | Auth                     |
|--------------------------|-----------------------------------------------------------------|--------------------------|
| `authfi.auth()`          | JWT verification — JWKS + RS256 (Nimbus)                        | n/a (verification only)  |
| `authfi.users()`         | User CRUD, role/group assignment, block/unblock                 | API key / service        |
| `authfi.orgs()`          | Org CRUD, members, SSO config, branding                          | API key / service        |
| `authfi.permissions()`   | Permission catalog sync, role-permission binding                 | API key / service        |
| `authfi.me()`            | `/me`, `/userinfo`, change own password, security-score          | end-user JWT             |
| `authfi.sessions()`      | List/revoke own sessions; admin per-user views                   | mixed                    |
| `authfi.mfa()`           | TOTP enroll/verify/list/unenroll                                  | end-user JWT             |
| `authfi.auditLogs()`     | Audit log search (limit/offset/since)                            | API key / service        |
| `authfi.invitations()`   | Programmatic invites — **backend not wired yet**                 | API key / service        |
| `authfi.tokenIntrospection()` | RFC 7662 introspect + RFC 7009 revoke                       | none (public)            |
| `authfi.discovery()`     | `.well-known/{openid-configuration, jwks, smart-configuration, agent-auth}` | none |
| `authfi.connect()`       | Cloud credentials — GCP, AWS, Azure, OCI                         | API key / service        |
| `authfi.agents()`        | Owner-driven agent registration (Phase 1)                         | end-user JWT             |
| `authfi.myAgents()`      | End-user portal for managing one's agents (Phase 4)               | end-user JWT             |
| `authfi.agentAuth()`     | AAP — token, request-approval, guard, can (Phase 2 & 3)           | agent_credentials        |
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

## What's NOT in v0.2.0

- **Spring AI advisor** for auto-gating `@Tool` calls with HIL approval — deferred to v0.2.1 (Spring AI 1.x dep version validation). The seamless `agent.guard(...)` API above is available from any Spring AI app today; the advisor would just wire it automatically.
- **InvitationsClient** is shipped but the backend routes are not yet wired (see [#TBD](https://github.com/queflyhq/authfi-auth-service/issues)). The client class is callable; calls return 404 until the routes ship.

## License

Apache-2.0
