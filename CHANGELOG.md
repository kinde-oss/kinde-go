<!-- Ideally, this should get auto-generated via tools like [auto-changelog](https://github.com/CookPete/auto-changelog). Eventually, this will get set up as part of the repository template. -->

## Unreleased

### Bug fixes

- **Management API:** `GetOrganizationConnections` (and other calls returning `get_connections_response`) now decode each entry in `connections` as a plain connection object (`id`, `name`, `display_name`, `strategy`), instead of the single-connection response envelope, which previously left those fields empty.
