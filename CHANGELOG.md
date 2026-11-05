# Changelog

All notable changes to this library (`io.authfi:authfi-sdk`). It follows [Semantic Versioning](https://semver.org):
before 1.0 a minor version may break, but only with an entry here.

## 0.4.0

### Changed

- **Token verification is strict, and `AuthFI.auth()` is replaced by `AuthFI.verifier(audience...)`.** The verifier
  accepts EdDSA, ES256, PS256 and RS256 tokens. It accepts only `typ` `at+jwt` (ID tokens are refused) and checks
  `iss`, `aud`, `exp`, `nbf`, `sub` and `tenant_id`. An audience is required and is never AuthFI's own. Tokens
  with `cnf` or a nested `act` are refused. **Breaking** for code that called `AuthFI.auth()`.
- Agents ask for their token at the token endpoint the authorization server advertises in its discovery document,
  and approvals are signed with the agent key at the advertised endpoints. The discovery path name is corrected.

### Fixed

- `AuthFIConfig`, `AuthFIProperties` and `AgentCredentials` print identifiers only, and `AuthFIException` and
  transport errors mask JWTs, PEM keys, AuthFI key shapes and the client's own secrets, so none of them reaches a
  log. A test fails if any marker secret appears in an output.

## 0.3.1

### Fixed

- The agent endpoints are read from discovery instead of built by hand. In 0.3.0 the agent token URL was
  assembled from the tenant and a version and returned 404, so every agent failed on its first call.

## 0.3.0

The first version on Maven Central.

### Changed

- The group id is `io.authfi`.
- Agents authenticate by signing a `private_key_jwt` assertion with their key, instead of sending a secret.
