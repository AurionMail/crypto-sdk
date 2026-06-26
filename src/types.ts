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
  getEncryptedH0(): Promise<Uint8Array | null>;
  saveEncryptedH0(encryptedH0: Uint8Array): Promise<void>;

  // 🔐 Pour les données génériques (ex: MailCredentials chiffrés, jetons, etc.)
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  clearAll(): Promise<void>;
}

export interface MemberKeyInfo {
  user_id: string;
  public_key: string; // Bloc de clé publique armored du membre
}

export interface RoutingSyncItem {
  identity_id: string;
  email: string;
  type: 'primary' | 'alias' | 'shared'; // primary = personnel, alias = alias, shared = groupe/partagé
  needs_key_gen: boolean;
  needs_key_fetch: boolean;
  encrypted_private_key?: string; // base64 blob si disponible
  wkd_hash?: string;
  members?: MemberKeyInfo[]; // Présent si needs_key_gen est true
}

export interface SyncRoutingResponse {
  identities: RoutingSyncItem[];
}

export interface KeySharePayload {
  user_id: string;
  encrypted_private_key: string; // Clé partagée chiffrée avec la clé publique du membre
}

export interface KeyUploadPayload {
  identity_id: string;
  armored_public_key: string;
  shares: KeySharePayload[];
}

export interface GroupMemberInput {
  user_id: string;
  public_key: string;
}

export interface GroupKeyMaterial {
  groupPublicKeyArmored: string;
  shares: KeySharePayload[];
}