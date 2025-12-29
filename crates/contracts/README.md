# Simplicity HL Core -- Contracts

This crate is a collection of contracts showcasing core possibilities of [Elements](https://docs.rs/elements) and [Simplicity HL](https://github.com/BlockstreamResearch/simfony).

Here you will find Simplicity HL implementations of [Options](https://blockstream.com/assets/downloads/pdf/options-whitepaper.pdf) (see [options](src/options)), Dual Currency Deposit Contract (see [dcd](src/dual_currency_deposit)), and more.

The module that stands out is [`sdk`](src/sdk). This module does not contain contract source code; instead, it provides builder functions to help build Elements transactions to issue assets or transfer native currency (see [basic](src/sdk/basic)), as well as builder functions for the Options contract.

This SDK can be used as a reference for how to build libraries targeting a particular Simplicity contract, integrateable with mobile/desktop, etc.

# Implementing contracts

This section describes how to implement a new contract following the structure used in this
repository. We use `array_tr_storage` as a running example (see the `options` contract for a
more complex case).

At a high level, contract development follows a staged process that mirrors Simplicity’s
execution model:
1. Implement the contract logic itself in SimplicityHL.
2. Bind build-time parameters using Rust.
3. Bind execution-time witness data using Rust.
4. Integrate the contract into the SDK infrastructure.

---

## Contract layout

Each contract follows the same directory structure:

```
new_contract/
    source_simf/
        new_contract.simf
    build_arguments.rs
    build_witness.rs
    mod.rs
```

Each file has a distinct role, explained below.

---

## 1. Contract logic (SimplicityHL)

Contract development starts with implementing the contract logic itself in **SimplicityHL**.
This logic is compiled to SIMF and stored under `source_simf/`.

Example:

```rust
fn hash_array_tr_storage(elem: u8, pair: (Ctx8, u16)) -> (Ctx8, u16) {
    let (ctx, i): (Ctx8, u16) = pair;

    match jet::eq_16(i, param::LEN) {
        // some logic
    }
}

fn main() {
    assert!(jet::eq_256(
        unwrap(jet::input_script_hash(jet::current_index())),
        unwrap(jet::output_script_hash(jet::current_index()))
    ));

    let tap_leaf: u256 = jet::tapleaf_hash();
    let ctx: Ctx8 = jet::tapdata_init();
    let storage: [u8; 10000] = witness::STORAGE;

    // contract-specific logic
    ...

    let hash_ctx3: Ctx8 = jet::sha_256_ctx_8_add_32(hash_ctx2, tweaked_key);

    assert!(jet::eq_256(
        jet::sha_256_ctx_8_finalize(hash_ctx3),
        unwrap(jet::input_script_hash(jet::current_index()))
    ));
}
```
### **Important**:
`param::LEN` and `witness::STORAGE` are placeholders. Their concrete values are provided later
by Rust code via `build_arguments.rs` and `build_witness.rs`.

## 2. Build-time arguments (build_arguments.rs)

Build-time arguments specialize the SIMF template by embedding constant values into the
contract.

```rust
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct UnlimitedStorageArguments {
    pub len: u16,
}

/// Build Simplicity arguments for the storage program.
#[must_use]
pub fn build_array_tr_storage_arguments(
    args: &UnlimitedStorageArguments
) -> Arguments {
    Arguments::from(HashMap::from([(
        // keyword used to access this value in the .simf code
        WitnessName::from_str_unchecked("LEN"),
        simplicityhl::Value::from(UIntValue::U16(args.len)),
    )]))
}

impl simplicityhl_core::Encodable for UnlimitedStorageArguments {}
```

## 3. Execution-time witness (build_witness.rs)

Execution-time data is supplied by the spender when the contract is executed. This data fills
witness nodes declared in the SIMF program.

```rust
use simplicityhl::types::UIntType;
use simplicityhl::value::{UIntValue, ValueConstructible};
use simplicityhl::{WitnessValues, str::WitnessName};

pub const MAX_VAL: usize = 10000;

#[must_use]
pub fn build_array_tr_storage_witness(
    storage: [u8; MAX_VAL]
) -> WitnessValues {
    let values: Vec<simplicityhl::Value> = storage
        .into_iter()
        .map(|value| simplicityhl::Value::from(UIntValue::from(value)))
        .collect();

    WitnessValues::from(HashMap::from([(
        // keyword used to access this value in the .simf code
        WitnessName::from_str_unchecked("STORAGE"),
        simplicityhl::Value::array(values, UIntType::U8.into()),
    )]))
}
```
Witness values:

- are provided at execution time;
- do not affect the contract hash;
- may vary from transaction to transaction.

If a value is provided by the spender and can change per execution, it belongs here.

## 4. Contract integration (mod.rs)

The mod.rs file integrates the contract into the Rust SDK and ties all components together.

```rust
// imports omitted

mod build_arguments;
mod build_witness;

pub use build_arguments::{
    UnlimitedStorageArguments,
    build_array_tr_storage_arguments,
};
pub use build_witness::{
    MAX_VAL,
    build_array_tr_storage_witness,
};

// Path to the SIMF source code
pub const ARRAY_TR_STORAGE_SOURCE: &str =
    include_str!("source_simf/array_tr_storage.simf");
```

This section:

- defines module boundaries;
- re-exports the public contract API;
- embeds the SIMF source code.

```rust
/// Get the storage template program for instantiation.
#[must_use]
pub fn get_array_tr_storage_template_program() -> TemplateProgram {
    TemplateProgram::new(ARRAY_TR_STORAGE_SOURCE)
        .expect("INTERNAL: expected to compile successfully.")
}

/// Get compiled storage program.
#[must_use]
pub fn get_array_tr_storage_compiled_program(
    args: &UnlimitedStorageArguments
) -> CompiledProgram {
    let program = get_array_tr_storage_template_program();

    program
        .instantiate(build_array_tr_storage_arguments(args), true)
        .unwrap()
}

/// Execute storage program.
pub fn execute_array_tr_storage_program(
    storage: [u8; MAX_VAL],
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_array_tr_storage_witness(storage);
    Ok(run_program(
        compiled_program,
        witness_values,
        env,
        TrackerLogLevel::None,
    )?.0)
}
```

This code:

- instantiates the SIMF template with build-time arguments;
- executes the compiled program with witness values;
- integrates with the Elements execution environment.

## 5. Testing

Contracts are typically tested by instantiating them with build arguments and executing them
with witness data in a simulated environment.

```rust
// imports omitted

#[test]
fn test_array_tr_storage_mint_path() -> Result<()> {
    let mut old_storage = [0u8; MAX_VAL];
    old_storage[3] = 0xff;

    let args = UnlimitedStorageArguments { len: 5 };

    // Instantiate and compile program
    let program = get_array_tr_storage_compiled_program(&args);
    let cmr = program.commit().cmr();

    // contract-specific test logic
    // ...

    assert!(
        execute_array_tr_storage_program(old_storage, &program, &env).is_ok(),
        "expected success mint path"
    );

    Ok(())
}
```

## License

Dual-licensed under either of:
- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
