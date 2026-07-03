---
name: Rust binary not portable across environments (Replit -> Plesk)
description: Why security-core's compiled `intel` binary can't be committed to git or copied between servers, and what deploy.sh must do instead.
---

The `security-core/target/release/intel` binary built in the Replit environment is dynamically
linked against glibc from a Nix store path (`/nix/store/.../glibc-.../ld-linux-x86-64.so.2`). It
will not execute on a standard Ubuntu/Debian VPS (e.g. a Plesk host) — the loader path doesn't
exist there.

**Why:** Replit's dev environment is NixOS-based; production Linux hosts use a different libc
loader path. A binary built in one is not portable to the other.

**How to apply:** Never assume a Rust (or any compiled) binary from this Replit workspace can ship
via git or file copy to another host. Always recompile from source on the target server as part of
its deploy process. For this project, `deploy.sh` builds `security-core` with `cargo build
--release` on the Plesk server itself (requires Rust installed there via rustup), and
`security-core/target/` stays gitignored. If a future deploy target also can't have a Rust
toolchain installed, a proper cross-compilation/static-musl build would be needed instead of just
copying the Replit-built binary.
