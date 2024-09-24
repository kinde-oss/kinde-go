# Kinde Go SDK

## This is work in progress, not ready for production usage. API is subject to change without warning.

The Kinde SDK for Go.

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Development

Requires Go 1.21+

### Usage

```bash
go get github.com/kinde-oss/kinde-go
go mod tidy
```

## Autorization code flow

```go
import (
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)
```

Example is in the test:

## Client credentials flow

```go
import (
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/kinde-oss/kinde-go/oauth2/client_credentials"
)
```

Example is in the test:

#### Manually requesting a token

```go
	token, err := kindeClient.GetToken(context.Background())
```

#### Using client to request an API endpoint

```go
  //This client will cache the token and re-fetch a new one as it expires
  client := kindeClient.GetClient(context.Background())

  //example call to Kinde Management API (client needs WithKindeManagementAPI(...))
  businessDetails, err := client.Get(fmt.Sprintf("%v/api/v1/business.json", os.Getenv("KINDE_SUB_DOMAIN")))

```

### SDK Development

1. Clone the repository to your machine:

   ```bash
   git clone https://github.com/kinde-oss/kinde-go.git
   ```

2. Go into the project:

   ```bash
   cd kinde-go
   ```

3. Install the dependencies:

   ```bash
   go mod download
   ```

## Documentation

For details on integrating this SDK into your project, head over to the [Kinde docs](https://kinde.com/docs/) and see the [Go SDK](<[link-to-kinde-doc](https://kinde.com/docs/developer-tools/)>) doc 👍🏼.

## Publishing

The core team handles publishing.

## Contributing

Please refer to Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/489e2ca9c3307c2b2e098a885e22f2239116394a/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.
