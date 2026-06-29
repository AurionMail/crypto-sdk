import * as AurionCryptoService from './services/crypto.service.js';

import { 
  AuthSessionState, 
  SaltResponse, 
  PublicKeyResponse, 
  GetEncryptedPrivateKeysResponse,
  GetServerLoginResponse,
  SyncRoutingResponse
} from './types.js';

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

  public async getSalts(email: string): Promise<SaltResponse & { id: string | null }> {
    const res = await fetch(`${this.apiBase}/auth/salt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    if (!res.ok) throw new Error('Erreur lors de la récupération des salts');
    return res.json();
  }

  public async signup(
    email: string, 
    h0: Uint8Array, 
    serverPasswordExternal: string, 
    EncryptedServerPassword: string,
    saltServer: string, 
    saltClient: string
  ): Promise<AuthSessionState> {
    // 1. Génération locale de h0 en RAM (Mot de passe -> Secret local abstrait)
   

    // 2. Génération de la preuve finale h1 en combinant h0 et le sel serveur
    const serverProof = AurionCryptoService.calculateServerProof(h0, saltServer);
    
    const res = await fetch(`${this.apiBase}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email, 
        password: serverProof,
        server_password: serverPasswordExternal,
        encrypted_server_password: EncryptedServerPassword,
        salt_client: saltClient, 
        salt_server: saltServer,
      })
    });

    if (!res.ok) throw new Error('Signup failed');
    return res.json();
  }

  public async login(email: string, password: string, saltServer: string): Promise<AuthSessionState & { data: any }> {
    
    // 1. Génération locale de h0 en RAM (Mot de passe -> Secret local abstrait)
    const h0 = AurionCryptoService.calculateH0(password);

    // 2. Génération de la preuve finale h1 en combinant h0 et le sel serveur
    const serverProof = AurionCryptoService.calculateServerProof(h0, saltServer);

    // 3. Envoi de la preuve au serveur sous la clé "password"
    const res = await fetch(`${this.apiBase}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: serverProof })
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

  public async validateSession(): Promise<{ user_id: string; email: string }> {
    if (!this.token) throw new Error('Not authenticated');

    const res = await fetch(`${this.apiBase}/auth/session`, {
      headers: this.getHeaders()
    });

    if (!res.ok) throw new Error('Session validation failed');
    return res.json();
  }

  public async getPublicKey(email: string): Promise<PublicKeyResponse> {
    const res = await fetch(`${this.apiBase}/keys/public/${encodeURIComponent(email)}`);

    if (res.status === 404) {
      throw new Error('Public key not found');
    }
    if (!res.ok) throw new Error('Failed to fetch public key');

    return res.json();
  }

  public async getEncryptedPrivateKey(): Promise<GetEncryptedPrivateKeysResponse> {
    if (!this.token) throw new Error('Not authenticated');

    const res = await fetch(`${this.apiBase}/keys/private/me`, {
      headers: this.getHeaders()
    });

    if (!res.ok) throw new Error('Failed to fetch encrypted private keys');
    return res.json() as Promise<GetEncryptedPrivateKeysResponse>;
  }

  /**
   * Récupère le mot de passe serveur chiffré de l'utilisateur authentifié
   */
  public async getServerLogin(): Promise<GetServerLoginResponse> {
    if (!this.token) throw new Error('Not authenticated');

    const res = await fetch(`${this.apiBase}/server`, {
      headers: this.getHeaders()
    });

    if (!res.ok) throw new Error('Failed to fetch server login credentials');
    return res.json() as Promise<GetServerLoginResponse>;
  }

  public async uploadPublicKey(email: string, armoredKey: string): Promise<{ id: string }> {
    const res = await fetch(`${this.apiBase}/keys/public`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        email,
        armored_key: armoredKey
      })
    });

    if (!res.ok) throw new Error('Public key upload failed');
    return res.json();
  }

  public async uploadPrivateKey(email: string, encryptedPrivateKey: string): Promise<{ id: string }> {
    const res = await fetch(`${this.apiBase}/keys/private`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        identity_email: email,
        encrypted_private_key: encryptedPrivateKey
      })
    });

    if (!res.ok) throw new Error('Private key upload failed');
    return res.json();
  }


public async verifyMailServer(email: string, serverPassword: string): Promise<{ status: string }> {
  const res = await fetch(`${this.apiBase}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, server_password: serverPassword })
  });

  if (!res.ok) throw new Error('Mail server authentication failed');
  return res.json();
}


public async syncRouting(): Promise<SyncRoutingResponse> {
  if (!this.token) throw new Error('Not authenticated');

  const res = await fetch(`${this.apiBase}/sync/routing`, {
    headers: this.getHeaders()
  });

  if (!res.ok) throw new Error('Failed to fetch routing sync state');
  return res.json() as Promise<SyncRoutingResponse>;
}


public async uploadSynchronizedKeys(payload: {
  identity_id: string;
  armored_public_key: string;
  shares: Array<{ user_id: string; encrypted_private_key: string }>;
}): Promise<void> {
  if (!this.token) throw new Error('Not authenticated');

  const res = await fetch(`${this.apiBase}/keys/sync`, {
    method: 'POST',
    headers: this.getHeaders(),
    body: JSON.stringify(payload)
  });

  if (!res.ok) throw new Error('Key synchronization upload failed');
}
}

