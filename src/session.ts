import * as openpgp from 'openpgp';
import MiniSearch from 'minisearch';
import * as AurionCryptoService from './services/crypto.service.js';
import { SecurityMode, EncryptedMail, ProcessedMailTokens, GroupKeyMaterial, MailIndexDoc, Base64CipherText, AurionStorageDriver } from './types.js';

export class AurionSession {
  public h0: Uint8Array | null = null;
  private pgpPrivateKey: openpgp.PrivateKey | null = null;
  private identitiesKeyring: Map<string, openpgp.PrivateKey> = new Map();
  private searchIndex: MiniSearch<MailIndexDoc>;
  private mode: SecurityMode | null = null;
  private storageDriver: AurionStorageDriver | null = null; // Injection du driver alternatif

  private static readonly STOP_WORDS = new Set([
    'le', 'la', 'les', 'de', 'des', 'un', 'une', 'et', 'en', 'du', 'au', 'aux', 'pour', 'dans', 'par', 'sur', 'qui', 'que', 'quoi', 'ce', 'cette',
    'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'it', 'this', 'that'
  ]);

  /**
   * Le constructeur accepte un driver de stockage optionnel pour découpler la persistance
   */
  constructor(storageDriver: AurionStorageDriver | null = null) {
    this.storageDriver = storageDriver;
    this.searchIndex = new MiniSearch<MailIndexDoc>({
      fields: ['text'],
      storeFields: ['id']
    });
  }

  public setPrimaryPrivateKey(privateKey: openpgp.PrivateKey): void {
    this.pgpPrivateKey = privateKey;
  }

  public getPrivateKeyForIdentity(email?: string): openpgp.PrivateKey {
    if (email && this.identitiesKeyring.has(email.toLowerCase())) {
      return this.identitiesKeyring.get(email.toLowerCase())!;
    }
    if (!this.pgpPrivateKey) throw new Error('No primary private key loaded in current AurionSession');
    return this.pgpPrivateKey;
  }

  /**
   * Restauration via le driver abstrait
   */
  public async tryAutoUnlock(): Promise<boolean> {
    if (!this.storageDriver) return false;

    try {
      const cryptoKey = await this.storageDriver.readMasterKey();
      if (!cryptoKey) return false;

      const rawBuffer = await crypto.subtle.exportKey('raw', cryptoKey);
      this.h0 = new Uint8Array(rawBuffer);
      this.mode = 'Confort';
      return true;
    } catch (error) {
      console.warn("Échec de la reconnexion automatique via le storage driver:", error);
      return false;
    }
  }

  public async unlockVault(password: string): Promise<void> {
    this.h0 = AurionCryptoService.calculateH0(password);
    
    if (this.mode === 'Confort' && this.storageDriver) {
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        this.h0.buffer as ArrayBuffer,
        { name: 'AES-GCM', length: 256 },
        true, // Nécessaire pour tryAutoUnlock via exportKey('raw')
        ['encrypt', 'decrypt']
      );
      await this.storageDriver.saveMasterKey(cryptoKey);
    } 
  }

  public async clearSession(): Promise<void> {
    this.h0 = null;
    this.pgpPrivateKey = null;
    this.identitiesKeyring.clear();
    this.mode = null;
    this.searchIndex = new MiniSearch<MailIndexDoc>({
      fields: ['text'],
      storeFields: ['id']
    });

    if (this.storageDriver) {
      await this.storageDriver.clearAll();
    }
  }

public async encryptForRecipients(
  recipientKeys: openpgp.PublicKey | openpgp.PublicKey[], 
  plaintext: string
): Promise<Base64CipherText> {
  return AurionCryptoService.encryptForRecipients(recipientKeys, plaintext);
}

  public async encryptForSelf(plaintext: string, identityEmail?: string): Promise<Base64CipherText> {
    return AurionCryptoService.encryptForSelf(this.getPrivateKeyForIdentity(identityEmail), plaintext);
  }

  public async decryptCiphertext(ciphertext: Base64CipherText, identityEmail?: string): Promise<string> {
    return AurionCryptoService.decryptCiphertext(this.getPrivateKeyForIdentity(identityEmail), ciphertext);
  }

  public async importPublicKey(armored: string): Promise<openpgp.PublicKey> {
    return openpgp.readKey({ armoredKey: armored });
  }

  public async generateGroupKeys(aliasEmail: string, memberPublicKeys: string[]): Promise<GroupKeyMaterial> {
    return AurionCryptoService.generateGroupKeys(aliasEmail, memberPublicKeys);
  }

  public async setPgpPrivateKey(armoredKey: string): Promise<void> {
    this.pgpPrivateKey = await openpgp.readPrivateKey({ armoredKey });
  }

  public extractSearchTokens(clearTextBody: string): string[] {
    const cleanHtml = clearTextBody
      .replace(/<style([\s\S]*?)<\/style>/gi, '')
      .replace(/<script([\s\S]*?)<\/script>/gi, '')
      .replace(/<[^>]+>/g, ' ');

    const normalized = cleanHtml.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const words = normalized.match(/\b[\w\d_-]+\b/g) || [];

    const uniqueTokens = new Set<string>();
    for (const word of words) {
      if (word.length > 1 && !AurionSession.STOP_WORDS.has(word)) uniqueTokens.add(word);
    }
    return Array.from(uniqueTokens);
  }

  public async search(query: string): Promise<string[]> {
    const normalizedQuery = query.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    return this.searchIndex.search(normalizedQuery).map(res => res.id);
  }

  public async processMailBatch(encryptedMails: Array<EncryptedMail>): Promise<Array<ProcessedMailTokens>> {
    const privateKey = this.getPrivateKeyForIdentity();
    const results: Array<ProcessedMailTokens> = [];

    for (const mail of encryptedMails) {
      let clearTextBody: string | null = null;
      try {
        clearTextBody = await AurionCryptoService.decryptCiphertext(privateKey, mail.body);
        const tokens = this.extractSearchTokens(clearTextBody);
        
        this.searchIndex.add({ id: mail.id, text: tokens.join(' ') });
        results.push({ id: mail.id, tokens });
      } finally {
        if (clearTextBody) clearTextBody = "";
        clearTextBody = null;
      }
    }
    return results;
  }

  public async decryptAndLoadPrivateKeys(
    encryptedKeys: Array<{ encrypted_private_key: string; identity_email?: string }>,
    saltClient: string
  ): Promise<openpgp.PrivateKey[]> {
    if (!this.h0) {
      throw new Error("Vault is locked. Call unlockVault first to generate h0.");
    }

    const pgpPassphrase = AurionCryptoService.derivePgpPassphrase(this.h0, saltClient);
    const decryptedKeys = await AurionCryptoService.decryptPrivateKeys(encryptedKeys, pgpPassphrase);

    for (let i = 0; i < decryptedKeys.length; i++) {
      const key = decryptedKeys[i];
      const metadata = encryptedKeys[i];

      if (metadata.identity_email) {
        this.identitiesKeyring.set(metadata.identity_email.toLowerCase(), key);
      } else {
        const userIds = key.getUserIDs();
        if (userIds.length > 0) {
          this.identitiesKeyring.set(userIds[0].toLowerCase(), key);
        }
      }

      if (i === 0 && !this.pgpPrivateKey) {
        this.setPrimaryPrivateKey(key);
      }
    }

    return decryptedKeys;
  }

  public loadSingleDecryptedKey(email: string, privateKey: openpgp.PrivateKey): void {
    this.identitiesKeyring.set(email.toLowerCase(), privateKey);
    if (!this.pgpPrivateKey) {
      this.setPrimaryPrivateKey(privateKey);
    }
  }

  public async syncGroupKeys(
    identityId: string,
    groupEmail: string,
    wkdHash: string,
    members: Array<{ user_id: string; public_key: string }>
  ): Promise<{
    identity_id: string;
    armored_public_key: string;
    wkd_hash: string;
    shares: Array<{ user_id: string; encrypted_private_key: string }>;
  }> {
    const memberArmoredPublicKeys = members.map(m => m.public_key);
    const groupMaterial = await AurionCryptoService.generateGroupKeys(groupEmail, memberArmoredPublicKeys);

    const armoredGroupPublicKey = groupMaterial.groupPublicKeyArmored;
    const sharesPayload: Array<{ user_id: string; encrypted_private_key: string }> = [];

    for (const m of members) {
      const memberKey = await openpgp.readKey({ armoredKey: m.public_key });
      const fingerprint = memberKey.getFingerprint();
      const encryptedShare = groupMaterial.encryptedShares[fingerprint];
      
      if (encryptedShare) {
        sharesPayload.push({
          user_id: m.user_id,
          encrypted_private_key: AurionCryptoService.toBase64(encryptedShare)
        });
      }
    }

    return {
      identity_id: identityId,
      armored_public_key: armoredGroupPublicKey,
      wkd_hash: wkdHash,
      shares: sharesPayload
    };
  }

  public async encryptMailCredentials(plaintext: string): Promise<string> {
    if (!this.h0) throw new Error("Vault is locked. Call unlockVault first to generate h0.");
    return AurionCryptoService.encryptMailCredentials(plaintext, this.h0);
  }

  public async decryptMailCredentials(combinedBase64: string): Promise<string> {
    if (!this.h0) throw new Error("Vault is locked. Call unlockVault first to generate h0.");
    return AurionCryptoService.decryptMailCredentials(combinedBase64, this.h0);
  }
  public isUnlocked(): boolean {
    return this.h0 !== null;
  }

  /**
 * Exporte l'ensemble du trousseau sous forme textuelle (sérialisable) pour les Workers
 */
public exportArmoredKeyring(): Array<{ email: string; armoredKey: string }> {
  const payload: Array<{ email: string; armoredKey: string }> = [];
  
  if (this.pgpPrivateKey) {
    payload.push({
      email: 'primary', // repère pour la clé primaire
      armoredKey: this.pgpPrivateKey.armor()
    });
  }

  for (const [email, privateKey] of this.identitiesKeyring.entries()) {
    payload.push({
      email,
      armoredKey: privateKey.armor()
    });
  }

  return payload;
}
}