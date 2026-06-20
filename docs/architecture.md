# Aurion Vault & Session Security Architecture

This document describes the Zero-Knowledge security architecture implemented in the `AurionSession` engine. It details how the master key $h_0$ is generated, managed, and isolated across memory (RAM) and local storage depending on the selected **Security Mode**.

## Key Generation & Cryptographic Context

The architecture revolves around $h_0$, the Master Crypto Key, which is never sent over the network in its raw form.

1. **Derivation:** $h_0$ is derived on the client side using Argon2id:

$$h_0 = \text{Argon2id}(\text{Password}, \text{StaticEmptySalt})$$

2. **Usage:** $h_0$ acts as the root of trust to derive PGP passphrases and to symmetrically encrypt local mail account credentials using WebCrypto (`AES-GCM-256`). It is the result of derivation of the password with no salt.

## Security Modes Comparison

The system offers three distinct operational strategies to balance user convenience and extreme privacy.

| Feature | 🛋️ Comfort Mode | 🛡️ Parano Mode | 🌋 Extreme Mode |
| --- | --- | --- | --- |
| **Mail Credentials on Server (Go)** | Encrypted | ❌ None | ❌ None |
| **Mail Credentials on Local Disk** | Yes (`IndexedDB`) | Yes (`IndexedDB`) | ❌ None (RAM Only) |
| **$h_0$ Persistence** | Encrypted in `IndexedDB` | ❌ None (RAM Only) | ❌ None (RAM Only) |
| **Behavior on Page Refresh (`F5`)** | Transparent auto‑unlock | Prompts for Aurion Password | Prompts for Aurion & Mail Passwords |
| **New Device Provisioning** | Aurion Password only | Aurion Password only | Aurion + Mail Passwords |



## Deep Dive: Architectural Behaviors

### Comfort Mode (Seamless Persistence)

Designed for the general public, this mode ensures the user only has to remember their Aurion password once.

* **Storage Matrix:** The remote server stores the public key, the encrypted PGP private key, and the encrypted mail bridge credentials. Locally, $h_0$ is imported into `IndexedDB` as an opaque `CryptoKey`.
* **`F5` Refresh Cycle:** Completely transparent. `tryAutoUnlock()` queries `IndexedDB`, exports the raw key bytes, reinstantiates $h_0$ in RAM, and restores the full session silently.

### Parano Mode (Strict Secret Separation)

The server remains completely blind to email access credentials, hosting only cryptography keys.

* **Storage Matrix:** The server hosts only public keys and encrypted PGP private keys. Mail account credentials are encrypted locally via `encryptMailCredentials(credentials, h0)` and saved in the browser's `IndexedDB` (e.g., inside an isolated application configuration store). **$h_0$ is strictly kept in RAM.**
* **`F5` Refresh Cycle:** Web HTTP tokens keep the app shell connected. However, reloading wipes the volatile RAM, destroying $h_0$ and the PGP keys. The UI detects that `session.h0` is `null` and overlays a discrete password banner. Once the user types their Aurion password, $h_0$ is instantly regenerated, allowing the app to transparently decrypt the local credentials stored in `IndexedDB`.

### Extreme Mode (Zero-Trace Ephemeral Session)

Maximum compliance for shared workstations or high-risk operational environments.

* **Storage Matrix:** No sensitive data ever touches the local disk. Both $h_0$, the private PGP keys, and the plain/encrypted mail credentials live exclusively inside the volatile memory space of the application state (e.g., a Zustand store).
* **`F5` Refresh Cycle:** A page reload purges the browser memory allocation entirely. While HTTP JMAP session tokens might survive to display basic folder trees, all message bodies revert to raw, undecryptable ciphertext blocks. The system prompts the user for both their Aurion password and their remote mail access password to link the ephemeral session again.

## Memory Isolation vs. Storage Design (`extractable`)

An intentional asymmetry exists between how $h_0$ is loaded into WebCrypto during transient operations versus how it is handled during long-term storage persistence.

```
                  ┌──────────────────────────────────────────┐
                  │          AurionSession (RAM)             │
                  │   this.h0 = Uint8Array [ 32 bytes ]      │
                  └────────────────────┬─────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
   [ Crypto Operations ]                                 [ Local Storage ]
  `crypto.service.ts`                                    `session.ts`
  `importWebCryptoKey()`                                 `persistToIndexedDB()`
  🔓 extractable: false                                  🔒 extractable: true
            │                                                     │
            ▼                                                     ▼
  Secured against XSS memory                             Allows `tryAutoUnlock()`
  extraction during run-time.                            to read back key on boot.

```

### Run-Time Operations (`extractable: false`)

Inside `crypto.service.ts`, calls to `encryptMailCredentials` and `decryptMailCredentials` instantiate short-lived `CryptoKey` handles with `extractable: false`.

> **Security Mandate:** This locks the cryptographic engine. Even if a malicious third-party script achieves Arbitrary Code Execution (XSS) while a mail processing batch is running, it cannot invoke `crypto.subtle.exportKey()` to steal the active cryptographic key material from the WebCrypto context.

### Long-Term Persistence (`extractable: true`)

Inside `session.ts`, the `persistToIndexedDB` method imports $h_0$ using `extractable: true` before writing it into the `AurionStorage` IndexedDB instance.

> **Operational Necessity:** WebCrypto drivers forbid saving raw bytes natively; keys must be stored as structured `CryptoKey` objects. When the app boots after an `F5` event, `tryAutoUnlock()` must read this object and convert it back into a standard `Uint8Array` via `crypto.subtle.exportKey('raw', key)` so the session class can reuse it for PGP passphrase derivations. Setting this to `false` on storage would permanently lock the key inside the database, triggering fatal `DOMException` errors upon restoration attempts.