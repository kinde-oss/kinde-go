# Kinde [technology name] generator

The generator for the [Kinde [technology name] SDK](<[link-to-sdk-repo](https://github.com/kinde-oss/kinde-auth-nextjs)>).

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Overview

This generator creates an SDK in [technology name] that can authenticate to Kinde using the Authorization Code grant or the Authorization Code with PKCE grant via the [OAuth 2.0 protocol](https://oauth.net/2/). It can also access the [Kinde Management API](https://kinde.com/api/docs/#kinde-management-api) using the client credentials grant.

Also, see the SDKs section in Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/main/.github/CONTRIBUTING.md).

## Usage

### Requirements

You will need the following tools to be able to generate the SDK.

**`<todo>`**

- [ ] Include details here on any tools required to use this generator, e.g. Docker. If none exist, remove the section altogether. **Note:** This is different to developing on the generator - see the Development section.

**`</todo>`**

### Initial set up

1. Clone the repository to your machine:

   ```bash
   git clone [https url]
   ```

2. Go into the project:

   ```bash
   cd [name-of-repo]
   ```

3. Install the OpenAPI Generator tool:

   https://openapi-generator.tech/docs/installation

### SDK generation

Run the following command to generate the SDK:

```bash
[insert cmd]
```

**Note:** The API specifications should always point to Kinde's hosted version: https://kinde.com/api/kinde-mgmt-api-specs.yaml. This is set via the ` -i` option in the [OpenAPI Generator CLI](https://openapi-generator.tech/docs/usage/), for example:

```bash
openapi-generator-cli generate -i https://kinde.com/api/kinde-mgmt-api-specs.yaml
```

The SDK gets outputted to: [insert path], which you can enter via:

```bash
cd [insert path]
```

## SDK documentation

[[technology name] SDK](<[link-to-kinde-doc](https://kinde.com/docs/developer-tools/)>)

## Development

**`<todo>`**

- [ ] Include details here on how to develop on this SDK, i.e. contribute to it. E.g., how to get the code running, test locally, build processes, etc.

**`</todo>`**

## Contributing

Please refer to Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/489e2ca9c3307c2b2e098a885e22f2239116394a/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.
