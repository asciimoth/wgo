# Repository Guidelines

This repo is a fok of original [wireguard-go](https://github.com/WireGuard/wireguard-go) so you can find more context and usage examples there.
We are going to refactor it for better fitting into [gonnect](https://github.com/asciimoth/gonnect) ecosystem and better reusabillity as a lib.
Unlike original wireguard-go this project is only a lib, not an executable tool.

## Testing
Use `just check` to runt all types of tests + linting.

## Coding Style & Naming Conventions
Follow standard Go formatting with tabs and `gofmt`; do not hand-format files.
Match existing platform file naming such as `*_linux.go`, `*_windows.go`, and `*_test.go`.

## Testing Guidelines
Place tests next to the package they cover and name files `*_test.go`.
Prefer table-driven tests for protocol logic and edge cases.
Always use `--race` while testing.

