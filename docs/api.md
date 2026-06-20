# Aurion SDK Technical Documentation

This documentation provides the API reference and usage guidelines for the `aurion-sdk` library. The SDK consists of three core pillars: `AurionApiClient` (network communication targeting the Core API v1), `AurionSession` (state, multi-identity PGP keyrings, and RAM index management), and `AurionCryptoService` (stateless WebCrypto and OpenPGP processing).



## Installation & Requirements

The SDK relies on the following runtime primitives and peer dependencies:

* **Runtime**: Modern Browser or Node.js environments supporting `globalThis.crypto` (WebCrypto API) and `fetch`.
* **Dependencies**: `openpgp` (v5+), `minisearch`, `@noble/hashes`.



## Data Types & Typings

```typescript
export type SecurityMode = 'Confort' | 'Parano' | 'Extreme';

export type Base64CipherText = string;

export interface SaltResponse {
  id: string | null;
  salt_server: string;
  salt_client: string;
}

export interface AuthSessionState {
  token: string;
  user_id: string;
  primary_email: string;
}

export interface PublicKeyResponse {
  email: string;
  armored_key: string;
}

export interface PrivateKeyResponse {
  identity_email: string;
  encrypted_private_key: string;
}

export interface GroupKeyMaterial {
  groupPrivateKeyEncrypted: openpgp.PrivateKey;
  encryptedShares: Record<string, string>; // Record<Fingerprint, ArmoredPGPMessage>
}

export interface EncryptedMail {
  id: string;
  body: Base64CipherText;
}

export interface ProcessedMailTokens {
  id: string;
  tokens: string[];
}

export interface MailIndexDoc {
  id: string;
  text: string;
}

```



## AurionApiClient Reference

The `AurionApiClient` manages direct JSON-based HTTPS communication with the Core Backend API v1.

### `constructor(apiBase: string)`

Initializes the client and cleans trailing slashes from the base URL string.

### `setToken(token: string | null): void`

Injects or rotates the active HTTP session Bearer token (`Authorization: Bearer <token>`).

### `async getSalts(email: string): Promise<SaltResponse>`

Retrieves the Argon2id salts required to process credentials. Returns deterministic fake salts if the user does not exist to mitigate user enumeration. Maps to `POST /auth/salt`.

### `async signup(email: string, clientPasswordHashed: string, serverPasswordExternal: string, saltServer: string, saltClient: string): Promise<AuthSessionState>`

Registers a new account identity after validating the external mail server credentials. Maps to `POST /auth/signup`.

### `async verifyMailServer(email: string, serverPassword: string): Promise<{ status: string }>`

Pre-validates IMAP/JMAP mail server credentials before starting registration workflows. Maps to `POST /auth/verify`.

### `async login(email: string, password: string, saltServer: string): Promise<AuthSessionState & { data: any }>`

Derives $h_0$ locally, computes the Zero-Knowledge server proof ($h_1$), transmits it under the payload key `password`, and automatically provisions the instance with the received Bearer token. Maps to `POST /auth/login`.

### `async validateSession(): Promise<{ user_id: string; email: string }>`

Verifies token status against backend session context. Maps to `GET /auth/session`.

### `async getPublicKey(email: string): Promise<PublicKeyResponse>`

Retrieves the active public key for a third-party identity. Maps to `GET /keys/public/:email`.

### `async getEncryptedPrivateKey(): Promise<{ keys: PrivateKeyResponse[] }>`

Retrieves all symmetrically encrypted PGP private keys across identities the authenticated user belongs to. Maps to `GET /keys/private/me`.

### `async syncRouting(): Promise<any>`

Fetches all identities, groups, and aliases linked to the user with actionable indicators (`needs_key_gen`, `needs_key_fetch`). Maps to `GET /sync/routing`.

### `async uploadSynchronizedKeys(payload: { identity_id: string, armored_public_key: string, wkd_hash: string, shares: Array<{ user_id: string, encrypted_private_key: string }> }): Promise<void>`

Pushes group public keys and distributed member encrypted shares to the backend server. Maps to `POST /keys/sync`.

### `async uploadPublicKey(email: string, armoredKey: string, wkdHash: string): Promise<{ id: string }>`

Registers a public key for a designated identity (WKD ready). Maps to `POST /keys/public`.

### `async uploadPrivateKey(email: string, encryptedPrivateKey: string): Promise<{ id: string }>`

Stores the user's encrypted private key envelope for a specific identity. Maps to `POST /keys/private`.



## AurionSession Reference

The `AurionSession` class governs active RAM states, executing decentralized cryptographic handling, search token indexing, and state permanence strategies.

### Properties

* `public h0: Uint8Array | null`: The volatile master key node derived from client credentials.
* `private identitiesKeyring: Map<string, openpgp.PrivateKey>`: Local secure multi-identity PGP private key mapping (`email -> openpgp.PrivateKey`).

### `async tryAutoUnlock(): Promise<boolean>`

*Exclusive to Comfort Mode.* Asynchronously evaluates IndexedDB (`AurionStorage`). If an opaque, non-extractable `CryptoKey` exists, it exports its raw layout into `this.h0`, configures state mode to `'Confort'`, and returns `true`.

### `async unlockVault(password: string): Promise<void>`

Calculates $h_0$ via stateless Argon2id parameters. If the execution parameters flag a `'Confort'` configuration pattern, it copies $h_0$ to IndexedDB via an opaque `AES-GCM` reference.

### `async clearSession(): Promise<void>`

Flushes $h_0$, purges the local identity keyring maps, clears the `MiniSearch` index tracking variables, and completely drops the `master_crypto_key` storage identifier within IndexedDB.

### `async encryptForRecipient(recipientKey: openpgp.PublicKey, plaintext: string): Promise<Base64CipherText>`

Wraps plaintext data targeted at an external identity public key layout.

### `async encryptForSelf(plaintext: string, identityEmail?: string): Promise<Base64CipherText>`

Converts local cleartext data into a encrypted message targeting the user's primary or aliased private key layout.

### `async decryptCiphertext(ciphertext: Base64CipherText, identityEmail?: string): Promise<string>`

Decrypts data by resolving the associated active identity or falling back to the master configuration sequence.

### `async setPgpPrivateKey(armoredKey: string): Promise<void>`

Asynchronously deserializes and updates the primary active PGP private key pointer in memory.

### `extractSearchTokens(clearTextBody: string): string[]`

Sanitizes raw strings (stripping `<style>`, `<script>`, HTML structures), applies lowercase text normalization (NFD), filters out stop words, and returns unique lowercase token matrices.

### `async search(query: string): Promise<string[]>`

Queries the isolated client RAM `MiniSearch` data schema and returns matching internal payload identifiers (`id[]`).

### `async processMailBatch(encryptedMails: Array<EncryptedMail>): Promise<Array<ProcessedMailTokens>>`

Iterates over encrypted arrays, conducts OpenPGP payload decryption, registers extracted content inside the RAM search index, and runs explicit variables wipe handling.

### `async decryptAndLoadPrivateKeys(encryptedKeys: Array<{ encrypted_private_key: string, identity_email?: string }>, saltClient: string): Promise<openpgp.PrivateKey[]>`

Uses $h_0$ and the client salt to compute the PGP unlocking passphrase, decrypts mass private blocks, and populates the local `identitiesKeyring` map using provided metadata or fallback user IDs.

### `loadSingleDecryptedKey(email: string, privateKey: openpgp.PrivateKey): void`

Manually mounts a pre-decrypted standalone private key reference into the session context keyring map.

### `async syncGroupKeys(identityId: string, groupEmail: string, wkdHash: string, members: Array<{ user_id: string, public_key: string }>): Promise<any>`

Orchestrates decentralized ECC group keypair generation and maps cryptographic PGP shares across server user metadata requirements. Encodes final share blocks to standard Base64.



## AurionCryptoService Reference

A completely stateless utility service driving computational WebCrypto and OpenPGP task architectures.

### `calculateH0(password: string): Uint8Array`

Derives the primary volatile seed node utilizing Argon2id over a fixed 16-byte empty salt structure.

### `calculateServerProof(h0: Uint8Array, saltServer: string): string`

Hashes $h_0$ against the remote verification salt to produce a hexadecimal Zero-Knowledge proof string.

### `derivePgpPassphrase(h0: Uint8Array, saltClient: string): Uint8Array`

Computes the symmetric derivation key used to wrap/unwrap internal OpenPGP private data arrays.

### `async importWebCryptoKey(keyData: Uint8Array): Promise<CryptoKey>`

Wraps raw key bytes into an opaque `AES-GCM 256` key reference. **Explicitly enforces `extractable: false**` to protect against runtime extraction via XSS.

### `async encryptMailCredentials(plaintext: string, h0: Uint8Array): Promise<string>`

Encrypts data payloads using an ephemeral 12-byte initialization vector (IV) via AES-GCM. Returns a single payload structured as `Base64(IV + Ciphertext)`.

### `async decryptMailCredentials(combinedBase64: string, h0: Uint8Array): Promise<string>`

Parses combined Base64 strings, strictly partitions memory using an explicit `.slice(0, 12)` data allocation for the IV, copies the residual ciphertext into an isolated `ArrayBuffer` view, and evaluates the cleartext.



## End-to-End Core Workflows

### 1. Bootstrapping User Session and Multi-Keyring

```typescript
import { AurionApiClient } from './api.js';
import { AurionSession } from './sessions.js';

const api = new AurionApiClient('https://api.aurion.network');
const session = new AurionSession();

const email = 'developer@aurion.email';

// Step 1: Query execution parameters
const salts = await api.getSalts(email);

// Step 2: Local unlock
await session.unlockVault('user-passphrase');

// Step 3: ZKP Server Authentication
const authState = await api.login(email, 'user-passphrase', salts.salt_server);

// Step 4: Mass download and initialize multi-identity keyring envelopes
const keyContainer = await api.getEncryptedPrivateKey();
await session.decryptAndLoadPrivateKeys(keyContainer.keys, salts.salt_client);

console.log("Multi-identity cryptographic keyring established in RAM.");

```

### 2. Multi-Identity Synchronization and Group Key Lifecycle

```typescript
// Synchronize cryptographic routing requirements from API v1
const routingState = await api.syncRouting();

for (const identity of routingState.identities) {
  // If the user belongs to a shared group workspace lacking encryption keys
  if (identity.type === 'shared' && identity.needs_key_gen) {
    
    // Generate decentralized group keys and map shares back to user UUIDs
    const payload = await session.syncGroupKeys(
      identity.identity_id,
      identity.email,
      identity.wkd_hash || "",
      identity.members
    );

    // Push E2EE shares to backend infrastructure
    await api.uploadSynchronizedKeys(payload);
    
    console.log(`Successfully generated and dispatched shares for group: ${identity.email}`);
  }
}

```