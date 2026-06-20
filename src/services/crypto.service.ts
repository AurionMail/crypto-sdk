import * as openpgp from 'openpgp';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import { Base64CipherText, GroupKeyMaterial } from '../types.js';

const ARGON2_CONFIG = {
  t: 3,           // Time cost
  m: 64 * 1024,   // Memory cost (64 MB)
  p: 1,           // Parallelism
  dkLen: 32       // Output length (256 bits)
} as const;

const STATIC_EMPTY_SALT = new Uint8Array(16);



export const utf8Encode = (str: string): Uint8Array => new TextEncoder().encode(str);
export const utf8Decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** Convertit une chaîne de caractères brute en Base64 standard de manière sûre en tâche de fond */
export function toBase64(str: string): string {
  const bytes = utf8Encode(str);
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  return btoa(binary);
}

/** Convertit une chaîne Base64 en sa chaîne de caractères originale */
export function fromBase64(b64: string): string {
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return utf8Decode(bytes);
}

/** Convertit un Uint8Array en chaîne Hexadécimale via une table de conversion pré-calculée */
const HEX_STRINGS = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_STRINGS[bytes[i]];
  }
  return hex;
}

/** Génère un sel cryptographique aléatoire au format Base64URL sans padding */
export function generateSalt(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** calcule h0 (sans sel) pour servir de clé maîtresse volatile */
export function calculateH0(password: string): Uint8Array {
  return nobleArgon2id(utf8Encode(password), STATIC_EMPTY_SALT, ARGON2_CONFIG);
}

/** Étape 2 du protocole ZKP : Re-hache h0 avec le sel serveur pour la transmission */
export function calculateServerProof(h0: Uint8Array, saltServer: string): string {
  const hashBytes = nobleArgon2id(h0, utf8Encode(saltServer), ARGON2_CONFIG);
  return toHex(hashBytes);
}

/** Dérive la clé de déchiffrement du trousseau de clés privées local */
export function derivePgpPassphrase(h0: Uint8Array, saltClient: string): Uint8Array {
  const derivedBytes = nobleArgon2id(h0, utf8Encode(saltClient), ARGON2_CONFIG);
  return derivedBytes;
}

/** Génère une clé opaque WebCrypto asymétrique AES-GCM non exportable */
export async function importWebCryptoKey(keyData: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    keyData.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false, // Protection stricte : Impossible d'extraire la clé via JS après injection
    ['encrypt', 'decrypt']
  );
}

export async function encryptForRecipient(recipientKey: openpgp.PublicKey, plaintext: string): Promise<Base64CipherText> {
  const message = await openpgp.createMessage({ text: plaintext });
  const encrypted = await openpgp.encrypt({ message, encryptionKeys: recipientKey });
  return toBase64(encrypted as string);
}

export async function encryptForSelf(privateKey: openpgp.PrivateKey, plaintext: string): Promise<Base64CipherText> {
  const publicKey = privateKey.toPublic();
  const message = await openpgp.createMessage({ text: plaintext });
  const encrypted = await openpgp.encrypt({ message, encryptionKeys: publicKey });
  return toBase64(encrypted as string);
}

export async function decryptCiphertext(privateKey: openpgp.PrivateKey, ciphertext: Base64CipherText): Promise<string> {
  const armored = fromBase64(ciphertext);
  const message = await openpgp.readMessage({ armoredMessage: armored });
  const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey });
  return data as string;
}

export async function generateGroupKeys(aliasEmail: string, memberPublicKeys: string[]): Promise<GroupKeyMaterial> {
  const { privateKey } = await openpgp.generateKey({
    type: 'ecc',
    userIDs: [{ name: aliasEmail, email: aliasEmail }],
  });

  const encryptedShares: Record<string, string> = {};

  for (const armoredPubKey of memberPublicKeys) {
    const memberKey = await openpgp.readKey({ armoredKey: armoredPubKey });
    const fingerprint = memberKey.getFingerprint();
    const encryptedKeyBundle = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: privateKey }),
      encryptionKeys: memberKey
    });
    encryptedShares[fingerprint] = encryptedKeyBundle as string;
  }

  return { groupPrivateKeyEncrypted: privateKey, encryptedShares };
}

/** Déchiffre en masse une liste de clés privées OpenPGP */
export async function decryptPrivateKeys(
  encryptedKeys: Array<{ encrypted_private_key: string }>,
  passphrase: Uint8Array
): Promise<openpgp.PrivateKey[]> {
  
  const privateKeyPromises = encryptedKeys.map(async (item) => {
    const armored = fromBase64(item.encrypted_private_key);
    return openpgp.readPrivateKey({ armoredKey: armored });
  });

  const privateKeys = await Promise.all(privateKeyPromises);
  const decryptedKeys: openpgp.PrivateKey[] = [];
  let pass = toHex(passphrase);

  for (const pk of privateKeys) {
    const decrypted = await openpgp.decryptKey({ privateKey: pk, passphrase: pass });
    decryptedKeys.push(decrypted);
  }

  return decryptedKeys;
}

/**
 * Chiffre les identifiants mail en utilisant la clé h0.
 * Retourne une chaîne Base64 contenant [IV (12 octets) + Ciphertext].
 */
export async function encryptMailCredentials(plaintext: string, h0: Uint8Array): Promise<string> {
  const cryptoKey = await importWebCryptoKey(h0);

  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const plaintextBytes = utf8Encode(plaintext);
  
  // FIX: Passer le buffer sous-jacent casté en ArrayBuffer
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    plaintextBytes.buffer as ArrayBuffer
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);

  const combinedBytes = new Uint8Array(iv.length + encryptedBytes.length);
  combinedBytes.set(iv, 0);
  combinedBytes.set(encryptedBytes, iv.length);

  const binaryString = Array.from(combinedBytes, (byte) => String.fromCharCode(byte)).join('');
  return btoa(binaryString);
}

/**
 * Déchiffre les identifiants mail à partir de la chaîne Base64 générée par encryptMailCredentials.
 */
export async function decryptMailCredentials(combinedBase64: string, h0: Uint8Array): Promise<string> {
  const cryptoKey = await importWebCryptoKey(h0);

  const binaryString = atob(combinedBase64);
  const combinedBytes = Uint8Array.from(binaryString, (char) => char.charCodeAt(0));

  const iv = combinedBytes.slice(0, 12);
  const ciphertextBytes = combinedBytes.slice(12);

  if (iv.length < 12) {
    throw new Error('Données chiffrées invalides ou corrompues (IV manquant)');
  }

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertextBytes.buffer as ArrayBuffer
  );

  return utf8Decode(new Uint8Array(decryptedBuffer));
}