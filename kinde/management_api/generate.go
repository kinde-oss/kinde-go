package management_api

//go:generate go run github.com/ogen-go/ogen/cmd/ogen --target . -package management_api --clean https://api-spec.kinde.com/kinde-management-api-spec.yaml
//go:generate go run fix_optstring.go
//go:generate go run fix_oneof.go
