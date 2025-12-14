# Simplicity HL Core -- CLI

This CLI showcases how to deploy and interact with Simplicity HL contracts.

It provides [basic](src/commands/basic.rs) and [options](src/commands/options.rs) CLIs.

Use `--help` to understand what each command can do.

The basic commands are tools for playing around with the options contract.

Refer to the [contracts README](../contracts/README.md) for more information about the contracts.

## How to Use

```bash
cargo run -p cli -- basic --help
cargo run -p cli -- options --help
```

See [example-run.md](assets/example-run.md) for actual usage of this CLI.

## License

Dual-licensed under either of:
- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
