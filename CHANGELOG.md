<!-- Ideally, this should get auto-generated via tools like [auto-changelog](https://github.com/CookPete/auto-changelog). Eventually, this will get set up as part of the repository template. -->

## Unreleased

### Features

- **Management API:** `CreateIdentityResponseIdentity` now also decodes the `identity_id` field the Kinde API returns when creating an identity for an existing enterprise connection (previously only `id` was recognized). Added `EffectiveIdentityID()` helper to read whichever field is populated.
