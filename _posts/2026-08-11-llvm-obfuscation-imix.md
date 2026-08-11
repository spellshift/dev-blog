---
layout: post
title: Obfuscating imix with LLVM passes
subtitle: 587 strings said eldritch, now 0 do
gh-repo: spellshift/realm
gh-badge: [star, fork, follow]
tags: [imix, obfuscation, llvm]
comments: true
mathjax: true
author: Hulto
---

## The mission

```bash
$ strings imix | grep -i eldritch | wc -l
587
```

That's 587 reasons a defender could instantly identify our agent as Realm's imix. We set out to get that number to **0** — and along the way we learned a lot about LLVM pass plugins, rustc's LLVM ABI, and the sneaky ways "eldritch" hides in a Rust binary.

The plan was simple on paper:

1. Use an LLVM pass (string encryption) to scramble every constant string at compile time.
2. Strip symbols so mangled names disappear.
3. Squash the remaining source-level leaks.

The reality was... more interesting.

## Building the LLVM pass plugin

We used [eshard/obfuscator-llvm](https://github.com/eshard/obfuscator-llvm), a maintained fork of Obfuscator-LLVM that exposes several passes as an out-of-tree LLVM plugin:

- `string-encryption` (module pass — XOR-encrypts global strings, decrypts at startup via a constructor)
- `flattening`, `split-basic-blocks`, `substitution`, `bogus` (function passes)

The critical constraint: **the plugin must be built against the same LLVM major version as the rustc toolchain you'll use**, and rustc bundles its *own* libLLVM. We targeted LLVM 20 (matching nightly-2025-08-01, rustc 1.90.0-nightly).

```bash
git clone https://github.com/eshard/obfuscator-llvm.git /tmp/obfuscator-llvm
cd /tmp/obfuscator-llvm

cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/usr/lib/llvm-20/lib/cmake/llvm \
  -DCMAKE_CXX_FLAGS="-fno-rtti" \
  -DBUILD_SHARED_LIBS=OFF

cmake --build build -j$(nproc)
```

The `-fno-rtti` flag matters — LLVM is compiled without RTTI, and the plugin will be loaded into a process (rustc) that already has LLVM loaded. Mixing RTTI settings across the plugin/LLVM boundary is a classic source of ABI breakage. You should get a `libLLVMObfuscator.so` (about 200KB).

## Loading the plugin into rustc

Rust nightly has had `-Z llvm-plugins` / `-C passes` support for a while. Load it with:

```bash
export IMIX_SERVER_PUBKEY=<your tavern pubkey>
cd realm/implants

cargo +nightly-2025-08-01 rustc --release --bin imix -- \
  -Z llvm-plugins=/tmp/obfuscator-llvm/build/libLLVMObfuscator.so \
  -C passes='string-encryption' \
  -C debuginfo=0
```

The binary built, the plugin loaded without undefined symbols. Success! ...except `strings | grep -i eldritch` still showed the strings. Which brings us to trap #1.

## Trap #1: cargo rustc only affects the final crate

`cargo rustc --bin imix` passes your flags to **only the imix crate**, not its dependencies. But almost all the interesting strings live in *dependencies*: `lib/eldritch`, `lib/pb`, `lib/transport`, `rustls`, `tera`, etc. They're compiled as separate crates, each with their own LLVM module, and the pass never touches them.

Fix: apply the flags to every crate with `RUSTFLAGS`:

```toml
# realm/implants/.cargo/config.toml
[build]
rustflags = [
  "-Zllvm-plugins=/tmp/obfuscator-llvm/build/libLLVMObfuscator.so",
  "-Cpasses=string-encryption",
]
```

Now every crate in the dependency graph gets the pass.

## Trap #2: plugin ↔ rustc LLVM ABI mismatch

With workspace-wide flags in place, the rebuild crashed on `rustls`:

```
error: rustc interrupted by SIGSEGV, printing backtrace
...librustc_driver...alloc...sync...Arc...SourceFile...drop_slow...
note: we would appreciate a report at https://github.com/rust-lang/rust
error: could not compile `rustls` (lib)
```

Deterministic SIGSEGV, in `SourceMap` teardown, right after compiling rustls. The tell: the plugin was built against **distro** LLVM 20 (`/usr/lib/llvm-20`), but rustc loads its **own** `libLLVM-20.1-rust-1.90.0-nightly.so`:

```bash
$ ldd /tmp/obfuscator-llvm/build/libLLVMObfuscator.so   # no libLLVM dependency!
$ ldd $(rustc --print sysroot)/lib/librustc_driver-*.so | grep llvm
libLLVM.so.20.1-rust-1.90.0-nightly => ...
```

The plugin has no `libLLVM.so` dependency — its symbols are satisfied by rustc's bundled LLVM at load time. But the plugin was *compiled against* distro LLVM headers (a different LLVM 20.x build). Same major version, different in-memory ABI → heap corruption when the pass runs.

We verified it's the pass, not the load:

- Plugin loaded, **no** `-Cpasses` → rustls compiles fine.
- Plugin loaded **with** `-Cpasses=string-encryption` → SIGSEGV, every time.

**Lesson:** build the plugin against the exact LLVM that rustc bundles, or against a toolchain that matches your distro LLVM. The binary-level fix is to build the plugin from a copy of rustc's LLVM source (the rust-src/LLVM used by the toolchain), or use an LLVM-version-matched prebuilt. If you're on LLVM 22-era rustc, you also need the `llvm/Plugins/PassPlugin.h` include path that recent eshard/obfuscator-llvm handles.

We also ruled out the OLLVM full-rustc path (Docker `ollvm-rust-1.70.0`) — too old for Realm's `edition = "2024"` workspace and its rustc ≥1.71 dependency requirements.

## Trap #3: pass limitations — what string-encryption won't touch

Even a working pass has blind spots. `StringObfuscatorPass::encodeAllStrings` only encrypts globals that:

1. are `constant` (i.e. immutable),
2. are **C strings** — `isCString()` returns true only if the data is NUL-terminated with no interior NULs.

Two important consequences:

- `file!()` / `module_path!()` and panic-location strings *are* emitted as NUL-terminated constants → covered.
- **prost-generated field names are not.** prost-derive emits the struct field name as a bare `[8 x i8] c"eldritch"` — **no trailing NUL** — so the pass skips it. We found `Tome.eldritch`'s field name in the final `.rodata` blob, unencrypted, because of exactly this check.

## Beyond the pass: auditing the 587

Even with a perfect pass, symbol names and non-NUL strings leak. Here's the breakdown we found in a stock release build:

| Source | Mechanism | Fix |
|---|---|---|
| ~500 hits | `file!()` panic-location strings (`lib/eldritch/.../impl.rs`) | `-Z location-detail=none` |
| ~80 hits | Rust mangled symbols (`_ZN106_$LT$eldritch_libassets...`) | `-C strip=symbols` |
| 3 hits | rust-embed paths (`install_service/main.eldritch`) | rename embedded file |
| 1 hit | `"eldritch_{}"` temp-file prefix | rename prefix |
| 1 hit | prost field name `Tome.eldritch` | rename field in generated code |

### Fix 1: `-Z location-detail=none`

Panic locations (`file!()`, `line!()`) dominate a Rust binary's string table — every `unwrap()`, every `panic!` format string pulls in a full source path. Nightly's `-Z location-detail=none` removes the file paths entirely (it's a known malware-dev trick for the same reason). This killed the bulk of the 587.

### Fix 2: `-C strip=symbols`

Realm's workspace already sets `[profile.release] strip = true`, but the `.cargo/config.toml` had `-Cstrip=debuginfo` in `rustflags`, which **overrode** the profile setting — leaving the full symbol table (`symtab`/`strtab`) in the release binary. All those `_ZN...eldritch_libagent...` mangled names were symbols, not rodata. Switching to `-Cstrip=symbols` (or dropping the flag entirely) removed them:

```toml
[target.release]
rustflags = ["-Cpanic=abort","-Cdebuginfo=0","-Cstrip=symbols","-Zlocation-detail=none","-Clink-arg=-s"]
```

### Fix 3: rename the embedded tome

imix embeds `install_scripts/install_service/main.eldritch` via rust-embed, and `install.rs` checks `embedded_file_path.ends_with("main.eldritch")`. The path string itself was baked into `.rodata`. Renamed the file to `main.svc` and updated the check (and the docs).

### Fix 4: `"eldritch_{}"`

`eldritch-libfile`'s `temp_file()` defaults to `format!("eldritch_{}", nanos)` — a literal string. Renamed to `"tmp_{}"`.

### Fix 5: the prost field name

This was the sneaky one. `pb::Tome` is generated from `eldritch.proto` (field `string eldritch = 1`). prost-derive emits the field name as data in **two** places:

1. The `Debug` impl — `builder.field("eldritch", &wrapper)`
2. The `merge_field` decode-error strings — `DecodeError::push("Tome", "eldritch")`

And because `decode_with_chacha::<Req, Resp>` is a generic `#[inline]`-ish path used by transport, those constants get **MIR-inlined into libtransport** — so fixing only the pb crate wasn't enough. The field name had to change at the source.

We renamed the Rust field `eldritch` → `script` (wire-compatible: protobuf uses field numbers, not names):

- `lib/pb/build.rs` post-processes regenerated code: `content.replace("eldritch", "script")`
- The checked-in `lib/pb/src/generated/eldritch.rs` is patched to match (so no-protoc builds agree)
- Callers updated: `imix/src/task.rs` and its tests

Since we weren't regenerating tavern's Go protobufs (no `protoc-gen-go` in this environment), we deliberately did the rename Rust-side in the generated source rather than in `eldritch.proto` — keeping the wire format and the Go bindings untouched. A follow-up could do it properly in the `.proto` with both codegens regenerated.

> A note on golem: it also has a `tome.eldritch` accessor, but that's its own local `ParsedTome` struct (unrelated to `pb::Tome`), so we left it alone. Don't blindly grep-and-replace — verify each hit is actually the generated proto type.

## Realm-side changes at a glance

Everything that changed in `spellshift/realm` to reach 0:

| File | Change |
|---|---|
| `implants/.cargo/config.toml` | `-Cstrip=debuginfo` → `-Cstrip=symbols`, added `-Zlocation-detail=none`; kept `-Cpanic=abort`/`-Cdebuginfo=0`/`-Clink-arg=-s` |
| `implants/imix/install_scripts/install_service/main.eldritch` | renamed → `main.svc` |
| `implants/imix/src/install.rs` | `ends_with("main.eldritch")` → `ends_with("main.svc")` |
| `docs/_docs/user-guide/imix.md` | install docs: `main.eldritch` → `main.svc` |
| `implants/lib/eldritch/stdlib/eldritch-libfile/src/std/temp_file_impl.rs` | `"eldritch_{}"` → `"tmp_{}"` |
| `implants/lib/pb/build.rs` | post-processes regenerated `eldritch.rs`: `replace("eldritch", "script")` |
| `implants/lib/pb/src/generated/eldritch.rs` | checked-in generated copy: `pub eldritch` → `pub script` (+ doc) |
| `implants/imix/src/task.rs` | `tome.eldritch` → `tome.script` |
| `implants/imix/src/tests/task_tests.rs` | 5 `Tome { eldritch: ... }` constructions → `script:` |

**Deliberately NOT included:**

- `implants/rust-toolchain` was flipped `1.91.1` → `nightly` during the OLLVM experiments, but that's stale cruft, not part of the fix — every working build pinned `+nightly-2025-08-01` explicitly. Revert it, or pin it to a specific nightly if you want it committed.
- The `-Zllvm-plugins` / `-Cpasses` flags were **left out** of the final config since the plugin/rustc LLVM ABI mismatch crashes the build on `rustls` (see Trap #2). They belong in the config only once the plugin is built against rustc's exact LLVM.

## The result

```bash
$ strings target/release/imix | grep -i eldritch | wc -l
0

$ grep -c -ia "eldritch" target/release/imix
0
```

587 → 0, both at the `strings` level and raw byte level. Binary also dropped from 12MB to 8.9MB (symbols gone, panic locations gone).

The binary still runs: `imix install` copies itself to `/usr/sbin/imixd`, registers a systemd unit, and the service is `active (running)` with callbacks to the C2.

## Step-by-step: LLVM obfuscation for Realm

Here's the full recipe, condensed.

### 1. Pick a nightly that matches your LLVM

Realm needs a recent nightly (`edition = "2024"`, `let`-chains). Confirm the bundled LLVM:

```bash
rustup toolchain install nightly-2025-08-01
rustc +nightly-2025-08-01 --version --verbose   # LLVM version: 20.1.8
```

### 2. Build the plugin against a matching LLVM

For LLVM 20 (Ubuntu 24.04: `apt install llvm-20-dev`):

```bash
git clone https://github.com/eshard/obfuscator-llvm.git
cmake -S obfuscator-llvm -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/usr/lib/llvm-20/lib/cmake/llvm \
  -DCMAKE_CXX_FLAGS="-fno-rtti"
cmake --build build -j$(nproc)
```

> **If you hit SIGSEGVs on large crates**, the plugin and rustc's bundled LLVM don't match. Build the plugin against rustc's exact LLVM source (from the toolchain's rust-src / `build/src/llvm`), or align your distro LLVM with the toolchain's LLVM version.

### 3. Wire it into the workspace

```toml
# realm/implants/.cargo/config.toml
[build]
rustflags = [
  "-Zllvm-plugins=/path/to/build/libLLVMObfuscator.so",
  "-Cpasses=string-encryption",
  "-Cpanic=abort",
  "-Cdebuginfo=0",
  "-Cstrip=symbols",
  "-Zlocation-detail=none",
]
```

Use `RUSTFLAGS` (config), **not** `cargo rustc` flags, so every dependency gets the pass.

### 4. Fix the leaks the pass can't see

- `-Z location-detail=none` — kill `file!()` strings.
- `-C strip=symbols` — kill mangled names (don't let `-Cstrip=debuginfo` shadow the profile's `strip=true`).
- Grep your source for your product name in **string literals**, **embedded file names**, and **proto field names**. `grep -rn '"<name>' --include=*.rs .` and check anything a proc-macro (`rust-embed`, `prost`) might re-emit as a constant.
- Remember: bare arrays (`[8 x i8] c"eldritch"` without NUL) defeat `isCString()`-based passes.

### 5. Verify

```bash
strings target/release/imix | grep -i eldritch | wc -l   # want: 0
grep -c -ia "eldritch" target/release/imix                # want: 0
./target/release/imix --help                              # still works
```

## What's next

- Build the plugin against rustc's exact bundled LLVM so `string-encryption` (and the CFG passes: `flattening`, `substitution`, `split-basic-blocks`) can run end-to-end without the SIGSEGV.
- Move the `Tome.eldritch` rename into `eldritch.proto` itself and regenerate both Rust and Go bindings.
- Consider `-Zlocation-detail=file` as a middle ground if you still want line numbers in dev builds.
- Wire the pass flags behind a cargo feature / Makefile target so release builds are one command: `make release-obfuscated`.
