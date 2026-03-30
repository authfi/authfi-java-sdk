# AuthFI Java SDK

Official Java SDK for [AuthFI](https://authfi.app) — the identity control plane.

## Install

Maven:
```xml
<dependency>
    <groupId>com.quefly.authfi</groupId>
    <artifactId>authfi-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start (Spring Boot)

```yaml
# application.yml
authfi:
  tenant: acme
  api-key: sk_live_...
```

```java
@RestController
public class UsersController {

    @Autowired AuthFI authfi;

    @GetMapping("/api/users")
    public List<User> getUsers(@RequestHeader("Authorization") String auth) {
        AuthFIClaims user = authfi.auth().verifyHeader(auth);
        authfi.auth().requirePermissions(user, "read:users");
        return userService.list();
    }
}
```

## Features

- **auth** — JWKS + RS256 token verification, claims parsing, role/permission checks
- **connect** — Cloud credential exchange (GCP/AWS/Azure/OCI)
- **manage** — Users, Orgs, Permissions CRUD + permission auto-sync
- **filter** — Jakarta Servlet filter (works with any servlet container)
- **spring** — Spring Boot auto-configuration

## Auth Modes

```java
// User-facing app
AuthFI authfi = AuthFI.client()
    .tenant("acme")
    .apiKey("sk_live_...")
    .build();

// Service (M2M)
AuthFI authfi = AuthFI.service()
    .tenant("acme")
    .clientId("FIC-abc123")
    .clientSecret("FIS-xyz...")
    .build();
```

## Cloud Credentials (AuthFI Connect)

```java
CloudCredentials gcp = authfi.connect().gcp("bigquery-reader");
CloudCredentials aws = authfi.connect().aws("s3-readonly");
```

## On-Behalf-Of

```java
String scopedToken = authfi.onBehalfOf(userAccessToken).token("read:patients");
```

## Running Tests

```bash
mvn test
```

25 unit tests — all passing.

## License

MIT
