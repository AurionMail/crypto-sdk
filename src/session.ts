import * as openpgp from 'openpgp';
import MiniSearch from 'minisearch';
import * as AurionCryptoService from './services/crypto.service.js';
import { SecurityMode, EncryptedMail, ProcessedMailTokens, GroupKeyMaterial, MailIndexDoc, Base64CipherText } from './types.js';

export class AurionSession {
  public h0: Uint8Array | null = null;
  private pgpPrivateKey: openpgp.PrivateKey | null = null;
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

  private getPrimaryPrivateKey(): openpgp.PrivateKey {
    if (!this.pgpPrivateKey) throw new Error('No private key loaded in current AurionSession');
    return this.pgpPrivateKey;
  }

  /**
   * Tente une restauration automatique de la session (Boot de l'appli)
   * Dédié exclusivement au Mode Confort (IndexedDB). Retourne true si le vault est déverrouillé.
   * const unlocked = await aurionSession.tryAutoUnlock();
if (unlocked) {
  // Mode Confort actif ! Tu peux directement télécharger les clefs privées chiffrées 
  // depuis l'API et exécuter decryptAndLoadPrivateKeys().
} else {
  // Rediriger vers l'écran de Login traditionnel (Parano / Extreme / Première connexion Confort)
}
   */
  public async tryAutoUnlock(): Promise<boolean> {
    if (typeof indexedDB === 'undefined') return false;

    try {
      const cryptoKey = await this.readKeyFromIndexedDB();
      if (!cryptoKey) return false;

      // Récupération des octets bruts de h0 depuis la CryptoKey opaque
      const rawBuffer = await crypto.subtle.exportKey('raw', cryptoKey);
      this.h0 = new Uint8Array(rawBuffer);
      this.mode = 'Confort';
      return true;
    } catch (error) {
      console.warn("Échec de la reconnexion automatique:", error);
      return false;
    }
  }

  /**
   * 🔑 Stratégies de Persistence & Session
   */
  public async unlockVault(password: string): Promise<void> {
   
    this.h0 = AurionCryptoService.calculateH0(password);

    if (this.mode === 'Confort') {
      await this.persistToIndexedDB(this.h0);
    } 
    
    // 🛡️ Mode 'Parano' & 🌋 Mode 'Extreme' :
    // h0 reste UNIQUEMENT dans la propriété `this.h0` en RAM.
    // Au rafraîchissement (F5), l'instance est détruite, h0 s'évapore, déclenchant le bandeau.
  }

  /**
   * 🧼 Nettoie la session en cours et efface les traces dans IndexedDB
   */
  public async clearSession(): Promise<void> {
    this.h0 = null;
    this.pgpPrivateKey = null;
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
      true, // Nécessaire pour tryAutoUnlock
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
        if (!db.objectStoreNames.contains('session')) {
          resolve(null);
          return;
        }
        const transaction = db.transaction('session', 'readonly');
        const getRequest = transaction.objectStore('session').get('master_crypto_key');

        getRequest.onsuccess = () => resolve(getRequest.result || null);
        getRequest.onerror = () => reject(getRequest.error);
      };

      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Routage vers le service Crypto délégataire
   */
  public async encryptForRecipient(recipientKey: openpgp.PublicKey, plaintext: string): Promise<Base64CipherText> {
    return AurionCryptoService.encryptForRecipient(recipientKey, plaintext);
  }

  public async encryptForSelf(plaintext: string): Promise<Base64CipherText> {
    return AurionCryptoService.encryptForSelf(this.getPrimaryPrivateKey(), plaintext);
  }

  public async decryptCiphertext(ciphertext: Base64CipherText): Promise<string> {
    return AurionCryptoService.decryptCiphertext(this.getPrimaryPrivateKey(), ciphertext);
  }

  public async importPublicKey(armored: string): Promise<openpgp.PublicKey> {
    return openpgp.readKey({ armoredKey: armored });
  }

  public async generateGroupKeys(aliasEmail: string, memberPublicKeys: string[]): Promise<GroupKeyMaterial> {
    return AurionCryptoService.generateGroupKeys(aliasEmail, memberPublicKeys);
  }

  public setPgpPrivateKey(armoredKey: string): void {
    openpgp.readPrivateKey({ armoredKey }).then(key => { this.pgpPrivateKey = key; });
  }

  /**
   * Indexation & Recherche en RAM (Blind Indexing)
   */
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

  /**
   * Traitement Batch & Nettoyage RAM agressif
   */
  public async processMailBatch(encryptedMails: Array<EncryptedMail>): Promise<Array<ProcessedMailTokens>> {
    const privateKey = this.getPrimaryPrivateKey();
    const results: Array<ProcessedMailTokens> = [];

    for (const mail of encryptedMails) {
      let clearTextBody: string | null = null;
      try {
        clearTextBody = await AurionCryptoService.decryptCiphertext(privateKey, mail.body);
        const tokens = this.extractSearchTokens(clearTextBody);
        
        this.searchIndex.add({ id: mail.id, text: tokens.join(' ') });
        results.push({ id: mail.id, tokens });
      }finally {
        // Purge critique mémoire RAM
        if (clearTextBody) clearTextBody = "";
        clearTextBody = null;
      }
    }
    return results;
  }

  public async decryptAndLoadPrivateKeys(
    encryptedKeys: Array<{ encrypted_private_key: string }>,
    saltClient: string
  ): Promise<openpgp.PrivateKey[]> {
    if (!this.h0) {
      throw new Error("Vault is locked. Call unlockVault first to generate h0.");
    }

    const pgpPassphrase = AurionCryptoService.derivePgpPassphrase(this.h0, saltClient);
    const decryptedKeys = await AurionCryptoService.decryptPrivateKeys(encryptedKeys, pgpPassphrase);

    if (decryptedKeys.length > 0) {
      this.setPrimaryPrivateKey(decryptedKeys[0]);
    }

    return decryptedKeys;
  }
}