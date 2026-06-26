import * as openpgp from 'openpgp';
import * as AurionCryptoService from './services/crypto.service.js';
import { SecurityMode, EncryptedMail, ProcessedMailTokens, GroupKeyMaterial, Base64CipherText, AurionStorageDriver, GroupMemberInput } from './types.js';
import { AurionSearch } from './search.js';

export class AurionSession {
  public h0: Uint8Array | null = null;
  private pgpPrivateKey: openpgp.PrivateKey | null = null;
  private identitiesKeyring: Map<string, openpgp.PrivateKey> = new Map();
  private mode: SecurityMode | null = null;
  private storageDriver: AurionStorageDriver | null = null; // Injection du driver alternatif

  public searchEngine: AurionSearch;

  /**
   * Le constructeur accepte un driver de stockage optionnel pour découpler la persistance
   */
  constructor(storageDriver: AurionStorageDriver | null = null) {
    this.storageDriver = storageDriver;
    this.searchEngine = new AurionSearch();
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
   * Remplit this.h0 de manière Zero-Knowledge et sécurisée contre les XSS
   */
  public async tryAutoUnlock(): Promise<boolean> {
    if (!this.storageDriver){ 
      this.mode = 'Parano';
      return false;}

    try {
      // 1. Récupération de la clé opaque non extractible et du blob chiffré
      const storageKey = await this.storageDriver.readMasterKey();
      const encryptedPayload = await this.storageDriver.getEncryptedH0();

      if (!storageKey || !encryptedPayload) { 
        this.mode = 'Parano';
        return false;
      }

      // 2. Extraction de l'IV (12 premiers octets) et du ciphertext
      if (encryptedPayload.length < 12) throw new Error("Payload h0 corrompu");
      const iv = encryptedPayload.slice(0, 12);
      const ciphertext = encryptedPayload.slice(12);

      // 3. Déchiffrement interne par l'API WebCrypto
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        storageKey,
        ciphertext
      );

      // 4. Initialisation sécurisée de h0 en RAM
      this.h0 = new Uint8Array(decryptedBuffer);
      this.mode = 'Confort';

      // 5. Restauration automatique de l'index de recherche
      await this.loadSearchIndexFromStorage();

      return true;
    } catch (error) {
      console.warn("Échec de la reconnexion automatique via le storage driver:", error);
      this.mode = 'Parano';
      return false;
    }
  }

  public async unlockVault(password: string, mode: SecurityMode = 'Confort'): Promise<void> {
    this.h0 = AurionCryptoService.calculateH0(password);
    this.mode = mode;

    if (this.mode === 'Confort' && this.storageDriver) {
      try {
        // 1. Génération d'une clé AES-GCM locale NON EXTRACTIBLE (extractable: false)
        const storageKey = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );

        // 2. Chiffrement de h0 avec cette clé locale
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedBuffer = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          storageKey,
          this.h0.buffer as ArrayBuffer
        );

        // 3. Assemblage [IV + Ciphertext]
        const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encryptedBuffer), iv.length);

        // 4. Persistance séparée (la clé opaque d'un côté, les données de l'autre)
        await this.storageDriver.saveMasterKey(storageKey);
        await this.storageDriver.saveEncryptedH0(combined);

      } catch (error) {
        console.error("Impossible de sécuriser la session en mode Confort:", error);
        // Fallback de sécurité en mode Parano si l'API WebCrypto échoue localement
        this.mode = 'Parano';
      }
    }

    // Restauration automatique de l'index de recherche si disponible (Modes Confort et Parano)
    if (this.mode !== 'Extreme') {
      await this.loadSearchIndexFromStorage();
    }
  }

  public async clearSession(): Promise<void> {
    this.h0 = null;
    this.pgpPrivateKey = null;
    this.identitiesKeyring.clear();
    this.mode = null;
    this.searchEngine.clear();

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

  public async generateGroupKeys(aliasEmail: string, memberPublicKeys: GroupMemberInput[]): Promise<GroupKeyMaterial> {
    return AurionCryptoService.generateGroupKeys(aliasEmail, memberPublicKeys);
  }

  public async setPgpPrivateKey(armoredKey: string): Promise<void> {
    this.pgpPrivateKey = await openpgp.readPrivateKey({ armoredKey });
  }

  public extractSearchTokens(clearTextBody: string): string[] {
    return this.searchEngine.extractSearchTokens(clearTextBody);
  }

  public async search(query: string, mailboxId?: string): Promise<string[]> {
    return this.searchEngine.search(query, mailboxId);
  }

  public async processMailBatch(encryptedMails: Array<EncryptedMail>): Promise<Array<ProcessedMailTokens>> {
    const privateKey = this.getPrivateKeyForIdentity();
    const results: Array<ProcessedMailTokens> = [];

    for (const mail of encryptedMails) {
      let clearTextBody: string | null = null;
      try {
        clearTextBody = await AurionCryptoService.decryptCiphertext(privateKey, mail.body);
        
        // Extraction et indexation via le searchEngine dédié
        // Note : s'assurer de passer les mailboxIds si disponibles, sinon tableau vide par défaut
        const mailboxIds = mail.mailboxIds || []; 
        this.searchEngine.indexMail(mail.id, mailboxIds, clearTextBody);
        
        const tokens = this.searchEngine.extractSearchTokens(clearTextBody);
        results.push({ id: mail.id, tokens });
      } finally {
        if (clearTextBody) clearTextBody = "";
        clearTextBody = null;
      }
    }
    await this.saveSearchIndexToStorage();
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
    // 1. On passe directement le tableau de membres (GroupMemberInput[]) au service, 
    // plus besoin de faire un .map(m => m.public_key)
    const groupMaterial = await AurionCryptoService.generateGroupKeys(groupEmail, members);

    // 2. Le service renvoie déjà les shares mappés par user_id avec le Base64 appliqué.
    // On a juste à reconstruire le payload pour l'API Go.
    return {
      identity_id: identityId,
      armored_public_key: groupMaterial.groupPublicKeyArmored,
      wkd_hash: wkdHash,
      shares: groupMaterial.shares
    };
  }

  public async encryptMailCredentials(plaintext: string): Promise<string> {
    if (!this.h0) throw new Error("Vault is locked. Call unlockVault first to generate h0.");
    return AurionCryptoService.encryptWithH0(plaintext, this.h0);
  }

  public async decryptMailCredentials(combinedBase64: string): Promise<string> {
    if (!this.h0) throw new Error("Vault is locked. Call unlockVault first to generate h0.");
    return AurionCryptoService.decryptWithH0(combinedBase64, this.h0);
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

// session.ts

  /**
   * Chiffre et persiste l'index de recherche MiniSearch actuel dans IndexedDB
   * Ne fait rien si le mode est 'Extreme' ou si aucun driver n'est présent.
   */
  public async saveSearchIndexToStorage(): Promise<void> {
    if (!this.storageDriver) return;
    if (this.mode === 'Extreme') {
      console.log('[SearchIndex] Persistance ignorée (Mode de sécurité : Extreme)');
      return;
    }
    if (!this.h0) throw new Error("Vault is locked. Cannot encrypt index without h0.");

    try {
      const jsonIndex = this.searchEngine.exportJSON();
      const serialized = JSON.stringify(jsonIndex);
      
      // Chiffrement symétrique avec h0 pour garantir le Zero-Knowledge local
      const encryptedIndex = await AurionCryptoService.encryptWithH0(serialized, this.h0);
      
      await this.storageDriver.setItem('local_search_index', encryptedIndex);
      console.log('[SearchIndex] Index local chiffré et sauvegardé avec succès.');
    } catch (error) {
      console.error('[SearchIndex] Échec de la sauvegarde de l\'index local :', error);
    }
  }

  /**
   * Récupère, déchiffre et charge l'index de recherche MiniSearch depuis IndexedDB
   */
  public async loadSearchIndexFromStorage(): Promise<boolean> {
    if (!this.storageDriver) return false;
    if (this.mode === 'Extreme') return false;
    if (!this.h0) throw new Error("Vault is locked. Cannot decrypt index without h0.");

    try {
      const encryptedIndex = await this.storageDriver.getItem('local_search_index');
      if (!encryptedIndex) {
        console.log('[SearchIndex] Aucun index local trouvé dans le stockage.');
        return false;
      }

      // Déchiffrement avec h0
      const serialized = await AurionCryptoService.decryptWithH0(encryptedIndex, this.h0);
      const jsonIndex = JSON.parse(serialized);
      
      this.searchEngine.importJSON(jsonIndex);
      console.log('[SearchIndex] Index local restauré en RAM avec succès.');
      return true;
    } catch (error) {
      console.warn('[SearchIndex] Échec du chargement ou du déchiffrement de l\'index local :', error);
      return false;
    }
  }

  /**
 * Orchestre la génération des clés de l'utilisateur lors de son premier onboarding.
 * * @param userEmail L'adresse e-mail de l'utilisateur qui s'enregistre
 */
public async generateOnboardingKeys(userEmail: string): Promise<{
  publicKeyArmored: string;
  privateKeyArmored: string;
}> {
  if (!userEmail || !userEmail.includes('@')) {
    throw new Error("[Session] L'adresse e-mail fournie pour l'onboarding est invalide.");
  }

  try {
    // Appel direct au service cryptographique du SDK
    const primaryKeyPair = await AurionCryptoService.generatePrimaryKeyPair(userEmail);

    return {
      publicKeyArmored: primaryKeyPair.publicKeyArmored,
      // Cette clé privée en clair sera récupérée en RAM par l'app d'onboarding
      // pour être chiffrée ensuite avec le mot de passe + salt
      privateKeyArmored: primaryKeyPair.privateKeyArmored
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(`[Session] Échec de la préparation des clés d'onboarding : ${msg}`);
  }
}
}