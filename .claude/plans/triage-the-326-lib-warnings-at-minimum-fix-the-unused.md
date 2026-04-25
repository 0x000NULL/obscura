# Plan: triage-the-326-lib-warnings-at-minimum-fix-the-unused

## Goal
Categorize the 326 lib warnings and fix the security-critical `unused Result` warnings on `RngCore::try_fill_bytes` calls so entropy failures cannot be silently masked.

## Steps
1. Run `cargo check --lib --message-format=short 2>&1 | tee target/lib-warnings.txt` and produce a tally (`grep '^warning' target/lib-warnings.txt | sort | uniq -c | sort -rn | head -40`) so the 326-warning population is grouped by lint name. Capture the breakdown in the PR description / TODO.md note (no separate doc file).
2. For each `try_fill_bytes` call site listed below in production lib code, replace `rng.try_fill_bytes(&mut buf);` with `rng.try_fill_bytes(&mut buf).expect("RNG entropy failure: try_fill_bytes returned Err");`. Using `.expect(...)` (instead of `.fill_bytes()`) keeps the explicit Err path visible and produces a clear panic message tied to entropy exhaustion.
3. Leave the existing `let _ = rng.try_fill_bytes(...)` sites in `crypto/audit.rs:368` and `crypto/side_channel_protection.rs:311` unchanged — they are already explicitly suppressed and emit no warning; converting them is a behavior change (panic vs. continue) and is out of scope for this warning-triage pass. Note them in the triage summary as "intentionally suppressed; revisit separately."
4. Skip the `src/bin/test_rand.rs` and `src/bin/simple_rng_test.rs` callers — they are bin diagnostics that already `.expect(...)` or print the Err, and they are not part of `--lib` warnings.
5. Re-run `cargo check --lib --message-format=short 2>&1 | grep -c '^warning'` to confirm the warning count dropped by exactly the number of fixed sites (12 expected).
6. Run `cargo test --lib --no-run` to confirm fixed call sites still compile in test cfg (the protocol_morphing test branch uses `StdRng` from a fixed seed — `try_fill_bytes` on `StdRng` cannot fail, so `.expect(...)` is safe there too).

## Files
- `src/networking/dns_over_https.rs` -- line 92: add `.expect(...)` to the `try_fill_bytes` call inside `DoHProvider::random()`.
- `src/networking/privacy/timing_obfuscator.rs` -- line 249: add `.expect(...)` to the batch-id RNG call inside `route_transaction`.
- `src/crypto/hardware_accel.rs` -- lines 362, 369, 376, 385: add `.expect(...)` to all four `try_fill_bytes` calls (seed, nonce, delay, batch size).
- `src/networking/padding.rs` -- lines 181, 198, 210, 500, 580: add `.expect(...)` to the five `try_fill_bytes` calls (padding generation, uniform padding, normal-distribution padding, jitter sleep, dummy-message interval).
- `src/networking/protocol_morphing.rs` -- lines 1272 and 1285: add `.expect(...)` to both `try_fill_bytes` calls (test-cfg StdRng branch and prod thread_rng branch).
- `src/crypto/constant_time.rs` -- line 469: add `.expect(...)` to the `try_fill_bytes` call in `constant_time_random_scalar`.

## Risks
- Panics on entropy failure: switching from silent-ignore to `.expect(...)` will turn a previously masked entropy failure into a panic. For OS-backed and ChaCha-backed RNGs in our paths this is the *correct* behavior, but any caller that previously relied on the call "succeeding with zeroed bytes" would change behavior. Audit shows no such caller — every site uses the buffer immediately for randomness, so a zeroed buffer would already be a security bug.
- The padding.rs:210 site reads `bytes` twice (computes `u` and `v` from the same fill). That's a pre-existing latent bug (u and v are identical) but is *not* in scope for warning triage; flag it in the triage summary, do not fix here.
- Triage breakdown step depends on `cargo check` succeeding. Per recent commit `6a26d3e`, lib build is restored; only ~16 bench errors remain. `--lib` should be clean.
- Warning-count delta of 12 assumes each site emits exactly one `unused_must_use` warning. If multiple lints fire on the same expression the delta could differ; that's diagnostic, not a failure.

## Verify
```
cargo check --lib --message-format=short 2>&1 | tee target/lib-warnings-after.txt | grep -c '^warning' > /dev/null
test $(grep -E 'try_fill_bytes\(&mut [a-zA-Z_]+\);$' src/networking/dns_over_https.rs src/networking/privacy/timing_obfuscator.rs src/crypto/hardware_accel.rs src/networking/padding.rs src/networking/protocol_morphing.rs src/crypto/constant_time.rs | wc -l) -eq 0
cargo test --lib --no-run
```

## Assumptions
- "Security-sensitive paths" includes all production-lib `try_fill_bytes` sites where the Result is dropped, not only the two files named in the todo. The todo says "etc.", so I extended the fix to every analogous lib site (12 total) for consistency rather than a partial fix.
- `.expect("RNG entropy failure: ...")` is preferred over switching to `.fill_bytes()`. Both eliminate the warning; `.expect(...)` matches the todo's framing ("silently dropping … can mask entropy failures") by making the failure explicit at the call site.
- Existing `let _ = rng.try_fill_bytes(...)` sites in `audit.rs` and `side_channel_protection.rs` are intentional suppressions that don't appear in the warning count, so they are out of scope for "fix the unused Result" warning-fix work.
- Bin-target diagnostic files (`test_rand.rs`, `simple_rng_test.rs`) are out of scope — the todo specifies "lib warnings".
- The full 326-warning triage is a *categorization* deliverable (grouped counts in commit message / TODO note), not a fix-everything sweep. The todo says "at minimum, fix the unused Result"; the rest is documented for follow-up.
- The protocol_morphing.rs:1272 site is inside a `#[cfg(test)]` branch but still part of the lib build under `--cfg test`. `.expect(...)` is safe there because `StdRng::try_fill_bytes` from a fixed seed cannot fail.
- The grep verify command checks no bare `try_fill_bytes(&mut <ident>);` lines remain in the six target files (each fixed call should now end with `.expect(...)`); 0 means all sites were rewritten.

## Blockers
Blockers: none

## Summary
Tally and document the 326 lib warnings, then convert 12 silent `try_fill_bytes` Result-drops in crypto and networking lib code into `.expect(...)` calls so entropy failures panic instead of silently producing zeroed buffers.
