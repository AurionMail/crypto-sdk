import * as openpgp from 'openpgp';
import MiniSearch from 'minisearch';
import * as AurionCryptoService from './services/crypto.service.js';
import { SecurityMode, EncryptedMail, ProcessedMailTokens, GroupKeyMaterial, MailIndexDoc, Base64CipherText } from './types.js';

export class AurionSession {
  public h0: Uint8Array | null = null;
  private pgpPrivateKey: openpgp.PrivateKey | null = null;
  
  // 🔑 Nouveau : Gestionnaire multi-clés pour les Alias et les Groupes (Map: Email -> Instance OpenPGP)
  private identitiesKeyring: Map<string, openpgp.PrivateKey> = new Map();
  
  private searchIndex: MiniSearch<MailIndexDoc>;
  private mode: SecurityMode | null = null;

  private static readonly STOP_WORDS = new Set([
    'le', 'la', 'les', 'de', 'des', 'un', 'une', 'et', 'en', 'du', 'au', 'aux', 'pour', 'dans', 'par', 'sur', 'qui', 'que', 'quoi', 'ce', 'cette',
    'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'it', 'this', 'that'
  ]);

  constructor() {
    this.searchIndex = new MiniSearch<MailIndexDoc>({
      fields: ['text'],
      storeFields: ['id']
    });
  }

  public setPrimaryPrivateKey(privateKey: openpgp.PrivateKey): void {
    this.pgpPrivateKey = privateKey;
  }

  /**
   * Récupère une clé privée spécifique depuis le Keyring.
   * Si aucun e-mail n'est fourni, bascule automatiquement sur la clé principale.
   */
  private getPrivateKeyForIdentity(email?: string): openpgp.PrivateKey {
    if (email && this.identitiesKeyring.has(email.toLowerCase())) {
      return this.identitiesKeyring.get(email.toLowerCase())!;
    }
    if (!this.pgpPrivateKey) throw new Error('No primary private key loaded in current AurionSession');
    return this.pgpPrivateKey;
  }

  public async tryAutoUnlock(): Promise<boolean> {
    if (typeof indexedDB === 'undefined') return false;

    try {
      const cryptoKey = await this.readKeyFromIndexedDB();
      if (!cryptoKey) return false;

      const rawBuffer = await crypto.subtle.exportKey('raw', cryptoKey);
      this.h0 = new Uint8Array(rawBuffer);
      this.mode = 'Confort';
      return true;
    } catch (error) {
      console.warn("Échec de la reconnexion automatique:", error);
      return false;
    }
  }

  public async unlockVault(password: string): Promise<void> {
    this.h0 = AurionCryptoService.calculateH0(password);
    if (this.mode === 'Confort') {
      await this.persistToIndexedDB(this.h0);
    } 
  }

  public async clearSession(): Promise<void> {
    this.h0 = null;
    this.pgpPrivateKey = null;
    this.identitiesKeyring.clear(); // 🧼 Nettoyage du multi-trousseau
    this.mode = null;
    this.searchIndex = new MiniSearch<MailIndexDoc>({
      fields: ['text'],
      storeFields: ['id']
    });

    if (typeof indexedDB !== 'undefined') {
      try {
        const request = indexedDB.open('AurionStorage', 1);
        request.onsuccess = (event: any) => {
          const db = event.target.result;
          if (db.objectStoreNames.contains('session')) {
            const transaction = db.transaction('session', 'readwrite');
            transaction.objectStore('session').delete('master_crypto_key');
          }
        };
      } catch (e) {
        console.error("Erreur lors du nettoyage d'IndexedDB:", e);
      }
    }
  }

  private async persistToIndexedDB(keyData: Uint8Array): Promise<void> {
    if (typeof indexedDB === 'undefined') return;

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData.buffer as ArrayBuffer,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    return new Promise((resolve, reject) => {
      const request = indexedDB.open('AurionStorage', 1);
      request.onupgradeneeded = (event: any) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('session')) db.createObjectStore('session');
      };
      request.onsuccess = (event: any) => {
        const db = event.target.result;
        const transaction = db.transaction('session', 'readwrite');
        const store = transaction.objectStore('session');
        const putRequest = store.put(cryptoKey, 'master_crypto_key');
        putRequest.onsuccess = () => resolve();
        putRequest.onerror = () => reject(putRequest.error);
      };
      request.onerror = () => reject(request.error);
    });
  }

  private readKeyFromIndexedDB(): Promise<CryptoKey | null> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('AurionStorage', 1);
      request.onupgradeneeded = (event: any) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('session')) db.createObjectStore('session');
      };
      request.onsuccess = (event: any) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('session')) { resolve(null); return; }
        const transaction = db.transaction('session', 'readonly');
        const getRequest = transaction.objectStore('session').get('master_crypto_key');
        getRequest.onsuccess = () => resolve(getRequest.result || null);
        getRequest.onerror = () => reject(getRequest.error);
      };
      request.onerror = () => reject(request.error);
    });
  }

  public async encryptForRecipient(recipientKey: openpgp.PublicKey, plaintext: string): Promise<Base64CipherText> {
    return AurionCryptoService.encryptForRecipient(recipientKey, plaintext);
  }

  // Permet de choisir l'identité émettrice pour chiffrer pour soi-même
  public async encryptForSelf(plaintext: string, identityEmail?: string): Promise<Base64CipherText> {
    return AurionCryptoService.encryptForSelf(this.getPrivateKeyForIdentity(identityEmail), plaintext);
  }

  // Tente de déchiffrer avec une identité spécifique, sinon utilise la clé par défaut
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
    const privateKey = this.getPrivateKeyForIdentity(); // Utilise la clé par défaut pour l'indexation batch
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

  /**
   * 🔥 MODIFIÉ : Déchiffre en masse et indexe intelligemment TOUTES les identités chargées
   * (Utile lors de l'appel à /keys/private/me ou via la liste extraite de /sync/routing)
   */
  public async decryptAndLoadPrivateKeys(
    encryptedKeys: Array<{ encrypted_private_key: string; identity_email?: string }>,
    saltClient: string
  ): Promise<openpgp.PrivateKey[]> {
    if (!this.h0) {
      throw new Error("Vault is locked. Call unlockVault first to generate h0.");
    }

    const pgpPassphrase = AurionCryptoService.derivePgpPassphrase(this.h0, saltClient);
    const decryptedKeys = await AurionCryptoService.decryptPrivateKeys(encryptedKeys, pgpPassphrase);

    // Indexation dans le multi-keyring local
    for (let i = 0; i < decryptedKeys.length; i++) {
      const key = decryptedKeys[i];
      const metadata = encryptedKeys[i];

      // Si le serveur nous a fourni l'e-mail de l'identité lié à la clé, on l'indexe précisément
      if (metadata.identity_email) {
        this.identitiesKeyring.set(metadata.identity_email.toLowerCase(), key);
      } else {
        // Fallback historique (OpenPGP userID)
        const userIds = key.getUserIDs();
        if (userIds.length > 0) {
          this.identitiesKeyring.set(userIds[0].toLowerCase(), key);
        }
      }

      // La première clé reste définie comme la clé maîtresse/principale de session
      if (i === 0 && !this.pgpPrivateKey) {
        this.setPrimaryPrivateKey(key);
      }
    }

    return decryptedKeys;
  }

  /**
   * Permet d'injecter manuellement une clé déchiffrée isolée directement 
   * dans le Keyring au cours du flux de traitement itératif de `/sync/routing`.
   */
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

    const parsedPrivateKey = await openpgp.readPrivateKey({ 
      armoredKey: groupMaterial.groupPrivateKeyEncrypted 
    });

    const armoredGroupPublicKey = parsedPrivateKey.toPublic().armor();
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
}