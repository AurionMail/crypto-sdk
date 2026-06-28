import * as openpgp from 'openpgp';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import { Base64CipherText, GroupKeyMaterial, GroupMemberInput } from '../types.js';

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

/** Génère une clé opaque WebCrypto symétrique AES-GCM non exportable */
export async function importWebCryptoKey(keyData: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    keyData.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false, // Protection stricte : clé non extractible en clair par JS
    ['encrypt', 'decrypt']
  );
}

// Dans ton fichier crypto service

/**
 * Chiffre un message pour un ou plusieurs destinataires (Multi-chiffrement PGP natif)
 */
export async function encryptForRecipients(
  recipientKeys: openpgp.PublicKey | openpgp.PublicKey[], 
  plaintext: string
) {
  const message = await openpgp.createMessage({ text: plaintext });
  
  // OpenPGP gère nativement les tableaux de clés sous encryptionKeys
  const keys = Array.isArray(recipientKeys) ? recipientKeys : [recipientKeys];
  
  const encrypted = await openpgp.encrypt({ 
    message, 
    encryptionKeys: keys 
  });
  
  return toBase64(encrypted);
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

// Nouvelle version ou wrapper de la fonction du SDK
export async function generateGroupKeys(
  aliasEmail: string, 
  members: GroupMemberInput[]
): Promise<GroupKeyMaterial> {
  
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc',
    userIDs: [{ name: aliasEmail, email: aliasEmail }],
    format: 'armored'
  });

  const shares = [];

  for (const member of members) {
    const memberKey = await openpgp.readKey({ armoredKey: member.public_key });
    const message = await openpgp.createMessage({ text: privateKey });
    
    const encryptedKeyBundle = await openpgp.encrypt({
      message,
      encryptionKeys: memberKey
    });
    
    shares.push({
      user_id: member.user_id,
      // Le btoa (Base64) est appliqué ici
      encrypted_private_key: btoa(encryptedKeyBundle as string) 
    });
  }

  return {
    groupPublicKeyArmored: publicKey,
    shares
  };
}

/** Déchiffre en masse une liste de clés privées OpenPGP */
export async function decryptPrivateKeys(
  encryptedKeys: Array<{ encrypted_private_key: string; identity_email?: string }>,
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
 * Chiffre symétriquement une chaîne de caractères avec la clé maîtresse h0 (AES-GCM 256).
 * Retourne une chaîne Base64 contenant [IV (12 octets) + Ciphertext].
 */
export async function encryptWithH0(plaintext: string, h0: Uint8Array): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    h0.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const encryptedBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoded);

  const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedBuffer), iv.length);

  // Conversion performante binaire -> Base64 (évite l'allocation massive de tableaux de chaînes)
  let binaryString = '';
  for (let i = 0; i < combined.length; i++) {
    binaryString += String.fromCharCode(combined[i]);
  }
  return btoa(binaryString);
}

/**
 * Déchiffre symétriquement une chaîne Base64 avec la clé maîtresse h0 (AES-GCM 256).
 */
export async function decryptWithH0(combinedBase64: string, h0: Uint8Array): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    h0.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const binaryString = atob(combinedBase64);
  const combined = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    combined[i] = binaryString.charCodeAt(i);
  }

  if (combined.length < 12) {
    throw new Error('Données chiffrées invalides ou corrompues (IV manquant)');
  }

  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  // Utilisation sécurisée et directe des Uint8Arrays (évite les bugs liés au partage d'ArrayBuffer)
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Génère une paire de clés OpenPGP (ECC) neuve pour l'onboarding initial.
 * Renvoie la clé publique et la clé privée en clair (armored).
 */
export async function generatePrimaryKeyPair(userEmail: string, pass: string): Promise<{
  publicKeyArmored: string;
  privateKeyArmored: string;
}> {
  try {
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'ecc',
      userIDs: [{ name: userEmail, email: userEmail }],
      passphrase: pass,
      format: 'armored'
    });

    return {
      publicKeyArmored: publicKey,
      privateKeyArmored: privateKey
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(`[CryptoSDK] Erreur génération paire de clés primaires : ${msg}`);
  }
}