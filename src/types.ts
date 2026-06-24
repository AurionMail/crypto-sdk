export type SecurityMode = 'Confort' | 'Parano' | 'Extreme';

export interface EncryptedMail {
  id: string;
  body: string; // Bloc de données chiffré par OpenPGP
  mailboxIds?: string[]; // Liste des IDs de dossiers (ex: ["inbox", "sent"])
}

export interface ProcessedMailTokens {
  id: string;
  tokens: string[];
}

export interface GroupKeyMaterial {
  groupPrivateKeyEncrypted: string; // String (Armored)
  groupPublicKeyArmored: string;    // String (Armored)
  encryptedShares: Record<string, string>;
}

export interface MailIndexDoc {
  id: string;
  mailboxIds: string[];        // Liste des IDs de dossiers (ex: ["inbox", "sent"])
  text: string;
}
export type Base64CipherText = string;


export interface NetworkConfig {
  apiBase: string;
}

export interface AuthSessionState {
  token: string;
  user_id: string;
  primary_email: string;
}

export interface SaltResponse {
  salt_server: string;
  salt_client: string;
}

export interface PublicKeyResponse {
  email: string;
  armored_key: string;
}

export interface PrivateKeyResponse {
  identity_email: string;
  encrypted_private_key: string;
}

export interface GetEncryptedPrivateKeysResponse {
  keys: PrivateKeyResponse[];
}

export interface GetServerLoginResponse {
  server_password_encrypted: string;
}

export interface AurionStorageDriver {
  // Pour la clé maîtresse volatile (CryptoKey binaire opaque)
  readMasterKey(): Promise<CryptoKey | null>;
  saveMasterKey(cryptoKey: CryptoKey): Promise<void>;
  deleteMasterKey(): Promise<void>;

  // 🔐 Pour les données génériques (ex: MailCredentials chiffrés, jetons, etc.)
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  clearAll(): Promise<void>;
}