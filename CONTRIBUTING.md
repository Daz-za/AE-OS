# Contributing to AE-OS

Thank you for your interest. AE-OS is at an early stage, and comments on the specification are as valuable as code.

## Ways to contribute

- **Questions and ideas:** open an issue.
- **Specification changes:** open an issue first to discuss the change, since it affects every implementation. Changes to `spec/` need matching test vectors.
- **Bug fixes and small improvements:** open a pull request directly.
- **Security issues:** follow [SECURITY.md](SECURITY.md) and report privately.

## Making a change

1. Fork the repository and create a branch from `main`.
2. Make the change, with tests for any new behavior. If you change the format or the verifier's messages, regenerate the shared test vectors with `python testvectors/generate.py`.
3. Run the checks:
   ```
   pip install -e "python[test]"
   pytest -q python/tests
   python examples/invoice_demo.py
   cd rust                        # when the format, the vectors or the Rust code changed
   cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
   ```
4. Commit with a sign-off (see below) and open a pull request against `main`.

Keep pull requests focused on one change. CI must pass before a pull request is merged.

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO). By adding a `Signed-off-by` line to each commit, you confirm that you wrote the change or otherwise have the right to submit it under the project's license.

Add the line automatically with `git commit -s`. It uses the name and email in your git configuration:

```
Signed-off-by: Your Name <you@example.com>
```

## License

Contributions are licensed under the [Apache License 2.0](LICENSE), the same license as the project, as stated in the README.

## What not to include

Do not include credentials, private keys, real customer or employer data, or confidential material in issues, commits or test fixtures. Use made-up example data such as `acme.example`.

## Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
