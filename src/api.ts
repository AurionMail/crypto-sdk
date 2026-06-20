import * as AurionCryptoService from './services/crypto.service';

import { 
  AuthSessionState, 
  SaltResponse, 
  PublicKeyResponse, 
  PrivateKeyResponse 
} from './types';

export class AurionApiClient {
  private apiBase: string;
  private token: string | null = null;

  constructor(apiBase: string) {
    this.apiBase = apiBase.replace(/\/$/, ''); // Nettoie le trailing slash éventuel
  }

  /**
   * Injecte ou met à jour le token de session Bearer
   */
  public setToken(token: string | null): void {
    this.token = token;
  }

  /**
   * Helper privé pour injecter les headers communs d'authentification
   */
  private getHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...extraHeaders
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  /**
   * Récupération des Sels utilisateur
   */
  public async getSalts(email: string): Promise<SaltResponse> {
    const res = await fetch(`${this.apiBase}/auth/salts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    if (!res.ok) throw new Error('Erreur lors de la récupération des salts');
    return res.json();
  }

  /**
   * Inscription d'un nouvel utilisateur
   */
  public async signup(email: string, password: string, saltServer: string, saltClient: string): Promise<any> {
    const res = await fetch(`${this.apiBase}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email, 
        password, 
        salt_server: saltServer, 
        salt_client: saltClient 
      })
    });

    if (!res.ok) throw new Error('Signup failed');
    return res.json();
  }

  /**
   * Connexion et dérivation h0 locale via Argon2id (Zero-Knowledge Proof of Password)
   */
 public async login(email: string, password: string, saltServer: string): Promise<AuthSessionState & { data: any }> {
    
    // 1. Génération locale de h0 en RAM (Mot de passe -> Secret local abstrait)
    const h0 = AurionCryptoService.calculateH0(password);

    // 2. Génération de la preuve finale h1 en combinant h0 et le sel serveur
    const serverProof = AurionCryptoService.calculateServerProof(h0, saltServer);

    // 3. Envoi de la preuve au serveur
    const res = await fetch(`${this.apiBase}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, proof: serverProof })
    });

    if (!res.ok) throw new Error('Invalid credentials');

    const data = await res.json();
    
    // Mise à jour du token d'instance
    this.setToken(data.token);

    return {
      token: data.token,
      user_id: data.user_id,
      primary_email: data.email,
      data
    };
  }

  /**
   * Validation de la session existante
   */
  public async validateSession(): Promise<any> {
    if (!this.token) throw new Error('Not authenticated');

    const res = await fetch(`${this.apiBase}/auth/session`, {
      headers: this.getHeaders()
    });

    if (!res.ok) throw new Error('Session validation failed');
    return res.json();
  }

  /**
   * Récupère la clé publique d'un destinataire tiers
   */
  public async getPublicKey(email: string): Promise<PublicKeyResponse> {
    const res = await fetch(`${this.apiBase}/keys/public/${encodeURIComponent(email)}`);

    if (res.status === 404) {
      throw new Error('Public key not found');
    }
    if (!res.ok) throw new Error('Failed to fetch public key');

    return res.json();
  }

  /**
   * Récupère sa propre clé privée chiffrée
   */
  public async getEncryptedPrivateKey(): Promise<PrivateKeyResponse> {
    if (!this.token) throw new Error('Not authenticated');

    const res = await fetch(`${this.apiBase}/keys/private/me`, {
      headers: this.getHeaders()
    });

    if (!res.ok) throw new Error('Failed to fetch encrypted private key');
    return res.json();
  }

  /**
   * Publication de la clé publique de l'identité (WKD ready)
   */
  public async uploadPublicKey(email: string, armoredKey: string, wkdHash: string): Promise<void> {
    const res = await fetch(`${this.apiBase}/keys/public`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        email,
        armored_key: armoredKey,
        wkd_hash: wkdHash
      })
    });

    if (!res.ok) throw new Error('Public key upload failed');
  }

  /**
   * Sauvegarde de sa propre clé privée (déjà chiffrée localement via la clé maîtresse)
   */
  public async uploadPrivateKey(email: string, encryptedPrivateKey: string): Promise<void> {
    const res = await fetch(`${this.apiBase}/keys/private`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        identity_email: email,
        encrypted_private_key: encryptedPrivateKey
      })
    });

    if (!res.ok) throw new Error('Private key upload failed');
  }
}