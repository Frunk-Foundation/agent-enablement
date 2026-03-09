# Dual Cognito App Clients for Named vs Ephemeral Credential Lifetimes

## Summary
Keep a single Cognito user pool, but split token issuance across two app clients so refresh-token lifetime follows `profileType`.

- `named` profiles use the long-lived client with `365 day` refresh validity.
- `ephemeral` profiles use a second app client with `7 day` refresh validity.

Any issuance for `profileType=ephemeral` uses the ephemeral app client, regardless of whether the session came from admin bootstrap or delegation redeem.

## Key Changes
- Add a second Cognito app client and stack output for ephemeral issuance.
- Make the credentials broker choose the Cognito app client by `profileType`.
- Make refresh-token renewal use the same client family that issued the token.
- Add `--profile-type` to admin bootstrap issue/place and persist the selected client id in the session bundle.
- Keep one user pool and one principal/session model.

## Implementation Changes
- Add `EphemeralUserPoolClientId` output and wire both app client ids into the credentials Lambda environment.
- In the broker:
  - use the ephemeral client for delegation redeem
  - use the correct client for refresh based on session metadata sent by the runtime
  - return the selected Cognito client id in auth/reference metadata
  - include `principal.profileType` in the broker response
- In admin bootstrap:
  - accept `--profile-type named|ephemeral`
  - send the selected profile type to the broker during seeded session issuance
- In runtime refresh:
  - send the cached Cognito client id back to the broker on `/v1/credentials/refresh`

## Test Plan
- Stack tests assert both app clients exist, their refresh validity differs, the extra output exists, and the Lambda environment receives both client ids.
- Broker tests cover:
  - named refresh uses the named client
  - ephemeral refresh uses the ephemeral client
  - delegation redeem uses the ephemeral client
  - ephemeral basic bootstrap returns the ephemeral client id and `principal.profileType`
- Admin bootstrap tests cover `--profile-type ephemeral` routing.
- Runtime refresh tests assert the cached Cognito client id is sent on refresh.

## Assumptions
- The real requirement is only different token lifetimes by `profileType`; separate pools are out of scope.
- Existing named sessions continue to use the existing long-lived client id.
- Ephemeral user cleanup is not part of this change.
