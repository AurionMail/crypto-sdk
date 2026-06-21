export type SecurityMode = 'Confort' | 'Parano' | 'Extreme';

export interface EncryptedMail {
  id: string;
  body: string; // Bloc de données chiffré par OpenPGP
}

export interface ProcessedMailTokens {
  id: string;
  tokens: string[];
}

export interface GroupKeyMaterial {
  groupPrivateKeyEncrypted: string;
  encryptedShares: Record<string, string>; // Record<PublicKeyFingerprint, EncryptedPrivateKeyBundle>
}

export interface MailIndexDoc {
  id: string;
  text: string;
}
export type Base64CipherText = string;

// ... (Conserver vos types précédents)

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