import * as openpgp from 'openpgp';
import MiniSearch from 'minisearch';
import * as AurionCryptoService from './services/crypto.service';
import { SecurityMode, EncryptedMail, ProcessedMailTokens, GroupKeyMaterial, MailIndexDoc, Base64CipherText } from './types';

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
   * Stratégies de Persistence & Session
   */
  public async unlockVault(password: string, client_salt: string, mode: SecurityMode): Promise<void> {
    this.mode = mode;
    this.h0 = AurionCryptoService.calculateH0(password);

    if (mode === 'Confort') {
      await this.persistToIndexedDB(this.h0);
    } else if (mode === 'Parano') {
      const b64Key = btoa(String.fromCharCode(...this.h0));
      sessionStorage.setItem('_aurion_transient_sk', b64Key);
    }
    // 'Extreme' -> la clé reste uniquement dans `this.masterKey` en RAM
  }

  private async persistToIndexedDB(keyData: Uint8Array): Promise<void> {
    if (typeof indexedDB === 'undefined') return;

    const cryptoKey = await AurionCryptoService.importWebCryptoKey(keyData);
    const request = indexedDB.open('AurionStorage', 1);
    
    request.onupgradeneeded = (event: any) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains('session')) db.createObjectStore('session');
    };

    request.onsuccess = (event: any) => {
      const db = event.target.result;
      const transaction = db.transaction('session', 'readwrite');
      transaction.objectStore('session').put(cryptoKey, 'master_crypto_key');
    };
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

    // 1. Dérivation de la passphrase locale (Argon2id de h0 + salt_client)
    const pgpPassphrase = AurionCryptoService.derivePgpPassphrase(this.h0, saltClient);

    // 2. Déchiffrement des structures de clés
    const decryptedKeys = await AurionCryptoService.decryptPrivateKeys(encryptedKeys, pgpPassphrase);

    // 3. Stockage volatile dans l'instance SDK de la clé primaire pour le batching
    if (decryptedKeys.length > 0) {
      this.setPrimaryPrivateKey(decryptedKeys[0]);
    }

    return decryptedKeys;
  }
}