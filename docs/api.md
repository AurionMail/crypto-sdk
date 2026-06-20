# Aurion SDK Technical Documentation

This documentation provides the API reference and usage guidelines for the `aurion-sdk` library. The SDK consists of three core pillars: `AurionApiClient` (network communication), `AurionSession` (state and RAM indexing management), and `AurionCryptoService` (cryptographic operations).


## Installation & Requirements

The SDK relies on the following runtime primitives and peer dependencies:

* **Runtime**: Modern Browser or Node.js environment supporting the `globalThis.crypto` (WebCrypto API) and `fetch` APIs.
* **Dependencies**: `openpgp` (v5+), `minisearch`, `@noble/hashes`.

## Data Types & Typings

The library exposes and consumes the following primary types:

```typescript
export type SecurityMode = 'Confort' | 'Parano' | 'Extreme';

export type Base64CipherText = string;

export interface SaltResponse {
  salt_server: string;
  salt_client: string;
}

export interface AuthSessionState {
  token: string;
  user_id: string;
  primary_email: string;
}

export interface PublicKeyResponse {
  armored_key: string;
}

export interface PrivateKeyResponse {
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

The `AurionApiClient` manages direct HTTPS communication with the backend API.

### `constructor(apiBase: string)`

Initializes the HTTP client and strips any trailing slashes from the base URL.

### `setToken(token: string | null): void`

Injects or rotates the active HTTP session Bearer token.

* **Usage**: Automatically invoked during `login()`, but can be manually called to restore a valid token.

### `async getSalts(email: string): Promise<SaltResponse>`

Retrieves both server and client Argon2id salts registered for a given email address.

### `async signup(email: string, password: string, saltServer: string, saltClient: string): Promise<any>`

Registers a new account identity onto the remote backend database.

### `async login(email: string, password: string, saltServer: string): Promise<AuthSessionState & { data: any }>`

Executes local $h_0$ extraction and ZKP calculation, authenticates against the server endpoint, and automatically provisions the client instance with the received Bearer token.

### `async validateSession(): Promise<any>`

Verifies the current active Bearer token status against the backend session context.

### `async getPublicKey(email: string): Promise<PublicKeyResponse>`

Retrieves the target user's OpenPGP public key via email lookup. Throws a `404` error if missing.

### `async getEncryptedPrivateKey(): Promise<PrivateKeyResponse>`

Retrieves the logged-in user's own symmetrically encrypted PGP private key payload. Requires authentication.

### `async uploadPublicKey(email: string, armoredKey: string, wkdHash: string): Promise<void>`

Publishes the identity's public key to make it available for third-party discovery (WKD compatible).

### `async uploadPrivateKey(email: string, encryptedPrivateKey: string): Promise<void>`

Backs up the local locally-encrypted PGP private key onto the remote backend infrastructure.

## AurionSession Reference

The `AurionSession` class acts as the active RAM environment, handling search token extraction, ephemeral key states, and platform-level lifecycle unlocks.

### Properties

* `public h0: Uint8Array | null`: The root master key derived from user credentials.
* `private pgpPrivateKey: openpgp.PrivateKey | null`: Decrypted key matching the local identity.

### `async tryAutoUnlock(): Promise<boolean>`

*Exclusive to Comfort Mode.* Attempts to fetch the opaque `CryptoKey` from IndexedDB (`AurionStorage`). If successful, it exports the raw bytes back into `this.h0`, switches the instance mode to `'Confort'`, and returns `true`. Returns `false` on failure or environment lack of support.

### `async unlockVault(password: string): Promise<void>`

Calculates $h_0$ locally. If the instance runs under the `'Confort'` specification, it asynchronously mirrors $h_0$ directly into IndexedDB via `persistToIndexedDB`.

### `async clearSession(): Promise<void>`

Wipes `this.h0`, unloads the internal PGP private key instances, Resets the internal `MiniSearch` instance, and drops the `master_crypto_key` target row from IndexedDB.

### `async encryptForRecipient(recipientKey: openpgp.PublicKey, plaintext: string): Promise<Base64CipherText>`

Encrypts data targeting an external recipient's public key envelope.

### `async encryptForSelf(plaintext: string): Promise<Base64CipherText>`

Converts local data into an immutable string envelope targeting the current user's primary public identifier.

### `async decryptCiphertext(ciphertext: Base64CipherText): Promise<string>`

Passes the base64 ciphertext to the decryption pipeline using the active private key.

### `async setPgpPrivateKey(armoredKey: string): Promise<void>`

Asynchronously deserializes and flags the primary active PGP private key in memory.

### `extractSearchTokens(clearTextBody: string): string[]`

Sanitizes HTML input string sequences (stripping `<style>`, `<script>`, and tags), normalizes characters (NFD), filters out predefined stop words, and returns an array of unique lowercase index tokens.

### `async search(query: string): Promise<string[]>`

Queries the local RAM `MiniSearch` index and returns matching record identifiers (`id[]`).

### `async processMailBatch(encryptedMails: Array<EncryptedMail>): Promise<Array<ProcessedMailTokens>>`

Iterates through a list of encrypted mail payloads, performs local PGP decryption, registers the extracted plaintext tokens inside the internal `MiniSearch` instance, and cleans up variables to minimize RAM overhead.

### `async decryptAndLoadPrivateKeys(encryptedKeys: Array<{ encrypted_private_key: string }>, saltClient: string): Promise<openpgp.PrivateKey[]>`

Uses $h_0$ along with the client salt to derive the PGP passphrase, decrypts the keys, and sets the first decrypted key as the session's primary private key.

## AurionCryptoService Reference

A stateless utility namespace conducting native CPU/GPU processing workflows.

### `calculateH0(password: string): Uint8Array`

Derives the master credential node using Argon2id with a static 16-byte empty salt allocation.

### `calculateServerProof(h0: Uint8Array, saltServer: string): string`

Hashes $h_0$ against the remote salt parameter to output a hexadecimal verification hash.

### `derivePgpPassphrase(h0: Uint8Array, saltClient: string): Uint8Array`

Derives the passphrase used to decrypt local or remote OpenPGP private key blocks.

### `async importWebCryptoKey(keyData: Uint8Array): Promise<CryptoKey>`

Imports raw bytes into an opaque `AES-GCM 256` WebCrypto reference. **Enforces `extractable: false**` to prevent programmatic memory extraction.

### `async encryptMailCredentials(plaintext: string, h0: Uint8Array): Promise<string>`

Encrypts text payloads using an ephemeral 12-byte initialization vector (IV) via AES-GCM. Returns a single payload structured as `Base64(IV + Ciphertext)`.

### `async decryptMailCredentials(combinedBase64: string, h0: Uint8Array): Promise<string>`

Parses a combined Base64 payload, isolates the first 12 bytes using memory allocation slicing (`.slice(0, 12)`), and decrypts the trailing buffer via AES-GCM.

## End-to-End Core Workflows

### 1. Authentication & Session Bootstrap

```typescript
import { AurionApiClient } from './api.js';
import { AurionSession } from './sessions.js';

const client = new AurionApiClient('https://api.aurion.network');
const session = new AurionSession();

// Step 1: Query execution salts
const salts = await client.getSalts('user@aurion.email');

// Step 2: Client-side cryptographic initialization
await session.unlockVault('my-secure-password'); 

// Step 3: Zero-Knowledge Server verification & authentication
const authData = await client.login('user@aurion.email', 'my-secure-password', salts.salt_server);

// Step 4: Fetch and activate localized private cryptographic key bundle
const keyPayload = await client.getEncryptedPrivateKey();
await session.decryptAndLoadPrivateKeys([keyPayload], salts.salt_client);

console.log("Session bootstrapped successfully. Cryptographic engine ready.");

```

### 2. Processing and Indexing Local Mails

```typescript
// Incoming encrypted emails fetched from the database
const rawMails = [
  { id: "mail_01", body: "SGVsbG8gV29ybGQ..." },
  { id: "mail_02", body: "TWVzc2FnZSBDb25maWRlbnRpZWw..." }
];

// Asynchronously decrypt and index the emails into memory
const tokenMapping = await session.processMailBatch(rawMails);

// Local client-side blind search execution over index references
const matchedIds = await session.search("confidentiel");
console.log("Matched Document IDs:", matchedIds); // Output: ["mail_02"]

```