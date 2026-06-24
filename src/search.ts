import MiniSearch from 'minisearch';
import { MailIndexDoc } from './types.js';

export class AurionSearch {
  private searchIndex: MiniSearch<MailIndexDoc>;

  private static readonly STOP_WORDS = new Set([
    'le', 'la', 'les', 'de', 'des', 'un', 'une', 'et', 'en', 'du', 'au', 'aux', 'pour', 'dans', 'par', 'sur', 'qui', 'que', 'quoi', 'ce', 'cette',
    'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'it', 'this', 'that'
  ]);

  constructor() {
    this.searchIndex = new MiniSearch<MailIndexDoc>({
      fields: ['text'],       // Champ indexé pour la recherche textuelle
      storeFields: ['id', 'mailboxIds'] // Champs conservés en RAM pour filtrage post-recherche
    });
  }

  /**
   * Extrait les tokens, nettoie le HTML et normalise (retire accents et stop-words)
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
      if (word.length > 1 && !AurionSearch.STOP_WORDS.has(word)) {
        uniqueTokens.add(word);
      }
    }
    return Array.from(uniqueTokens);
  }

  /**
   * Indexation d'un document unique déchiffré
   */
  public indexMail(id: string, mailboxIds: string[], clearTextBody: string): void {
    const tokens = this.extractSearchTokens(clearTextBody);
    
    // Si le document existe déjà (ex: mise à jour des dossiers), on le supprime d'abord
    if (this.searchIndex.has(id)) {
      this.searchIndex.remove({ id } as any);
    }

    this.searchIndex.add({
      id,
      mailboxIds,
      text: tokens.join(' ')
    });
  }

  /**
   * Exécute la recherche locale en RAM avec filtre optionnel par dossier (mailboxId)
   */
  public search(query: string, mailboxId?: string): string[] {
    if (!query || query.trim() === "") {
      // Si la requête textuelle est vide mais qu'un dossier est ciblé, MiniSearch n'est pas adapté.
      // On retourne un tableau vide : ce cas sera géré par un Email/get filtré classique dans le client.
      return [];
    }

    const normalizedQuery = query.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    
    const results = this.searchIndex.search(normalizedQuery, {
      filter: mailboxId 
        ? (doc) => doc.mailboxIds.includes(mailboxId) 
        : undefined
    });

    return results.map(res => res.id);
  }

  /**
   * Vide complètement l'index (utile lors de la déconnexion / verrouillage)
   */
  public clear(): void {
    this.searchIndex.removeAll();
  }

  /**
   * Exporte l'index sous forme d'objet JSON sérialisable
   */
  public exportJSON(): any {
    return this.searchIndex.toJSON();
  }

  /**
   * Recharge l'index complet à partir d'un objet JSON importé
   */
  public importJSON(jsonIndex: any): void {
    this.searchIndex = MiniSearch.loadJSON(jsonIndex, {
      fields: ['text'],
      storeFields: ['id', 'mailboxIds']
    });
  }
  public hasDocument(id: string): boolean {
    return this.searchIndex.has(id);
  }
}