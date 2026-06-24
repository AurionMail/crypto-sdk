import { AurionStorageDriver } from '../types.js';

export class AurionIndexedDBDriver implements AurionStorageDriver {
  private dbName: string;
  private storeName: string;
  private keyName: string;

  constructor(dbName = 'AurionStorage', storeName = 'session', keyName = 'master_crypto_key') {
    this.dbName = dbName;
    this.storeName = storeName;
    this.keyName = keyName;
  }

  private getDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);

      request.onupgradeneeded = (event: any) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName);
        }
      };

      request.onsuccess = (event: any) => resolve(event.target.result);
      request.onerror = () => reject(request.error);
    });
  }

  // --- Gestion de la Clé Maîtresse (CryptoKey) ---

  public async readMasterKey(): Promise<CryptoKey | null> {
    if (typeof indexedDB === 'undefined') return null;
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.get(this.keyName); // 'master_crypto_key'
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  public async saveMasterKey(cryptoKey: CryptoKey): Promise<void> {
    if (typeof indexedDB === 'undefined') return;
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.put(cryptoKey, this.keyName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  public async getEncryptedH0(): Promise<Uint8Array | null> {
    if (typeof indexedDB === 'undefined') return null;
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.get('encrypted_h0_payload');

      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  public async saveEncryptedH0(payload: Uint8Array): Promise<void> {
    if (typeof indexedDB === 'undefined') return;
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.put(payload, 'encrypted_h0_payload');

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  public async deleteMasterKey(): Promise<void> {
    if (typeof indexedDB === 'undefined') return;
    const db = await this.getDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.delete(this.keyName);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  // --- 🔐 Nouvelles méthodes : Gestion des chaînes génériques (MailCredentials chiffrés) ---

  public async getItem(key: string): Promise<string | null> {
    if (typeof indexedDB === 'undefined') return null;
    const db = await this.getDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.get(key);

      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  public async setItem(key: string, value: string): Promise<void> {
    if (typeof indexedDB === 'undefined') return;
    const db = await this.getDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.put(value, key); // Stockage sous la clé choisie (ex: 'mail_creds')

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  public async removeItem(key: string): Promise<void> {
    if (typeof indexedDB === 'undefined') return;
    const db = await this.getDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.delete(key);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
  public async clearAll(): Promise<void> {
    if (typeof indexedDB === 'undefined') return;
    const db = await this.getDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.clear(); // 🧨 Vide l'intégralité du store (clés maîtresses, credentials parano, etc.)

      request.onsuccess = () => {
        db.close(); // Fermeture propre de la connexion après opération
        resolve();
      };
      request.onerror = () => reject(request.error);
    });
  }
}