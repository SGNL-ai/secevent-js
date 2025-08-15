/**
 * Security Event Token Signing utilities
 * Provides various signing strategies and key management
 */

import { generateKeyPair, importJWK, importPKCS8, importSPKI, KeyLike } from 'jose';
import { SigningKey } from '../types/secevent';

/**
 * Supported algorithms
 */
export enum Algorithm {
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',
  ES256 = 'ES256',
  ES384 = 'ES384',
  ES512 = 'ES512',
  HS256 = 'HS256',
  HS384 = 'HS384',
  HS512 = 'HS512',
}

/**
 * Key manager for handling signing keys
 */
export class KeyManager {
  private keys: Map<string, SigningKey> = new Map();

  /**
   * Add a key to the manager
   */
  addKey(kid: string, key: SigningKey): void {
    this.keys.set(kid, { ...key, kid });
  }

  /**
   * Get a key by ID
   */
  getKey(kid: string): SigningKey | undefined {
    return this.keys.get(kid);
  }

  /**
   * Get all keys
   */
  getAllKeys(): SigningKey[] {
    return Array.from(this.keys.values());
  }

  /**
   * Remove a key
   */
  removeKey(kid: string): boolean {
    return this.keys.delete(kid);
  }

  /**
   * Clear all keys
   */
  clear(): void {
    this.keys.clear();
  }

  /**
   * Get the default key (first key added)
   */
  getDefaultKey(): SigningKey | undefined {
    const firstKey = this.keys.values().next();
    return firstKey.done ? undefined : firstKey.value;
  }
}

/**
 * Signing utilities
 */
export class SigningUtils {
  /**
   * Generate a new key pair
   */
  static async generateKeyPair(
    alg: Algorithm = Algorithm.RS256,
    options?: { modulusLength?: number; extractable?: boolean },
  ): Promise<{ publicKey: KeyLike; privateKey: KeyLike }> {
    return generateKeyPair(alg, options);
  }

  /**
   * Import a JWK
   */
  static async importJWK(jwk: Record<string, unknown>, alg: Algorithm): Promise<KeyLike> {
    const result = await importJWK(jwk as unknown as Parameters<typeof importJWK>[0], alg);
    return result as KeyLike;
  }

  /**
   * Import a PKCS8 private key
   */
  static async importPrivateKey(
    pkcs8: string,
    alg: Algorithm,
    options?: { extractable?: boolean },
  ): Promise<KeyLike> {
    return importPKCS8(pkcs8, alg, options);
  }

  /**
   * Import a SPKI public key
   */
  static async importPublicKey(
    spki: string,
    alg: Algorithm,
    options?: { extractable?: boolean },
  ): Promise<KeyLike> {
    return importSPKI(spki, alg, options);
  }

  /**
   * Create a signing key from various formats
   */
  static async createSigningKey(
    key: string | KeyLike | Record<string, unknown>,
    alg: Algorithm,
    kid?: string,
  ): Promise<SigningKey> {
    let keyLike: KeyLike;

    if (typeof key === 'string') {
      // Assume it's a PEM-encoded key
      if (key.includes('PRIVATE KEY')) {
        keyLike = await this.importPrivateKey(key, alg);
      } else if (key.includes('PUBLIC KEY')) {
        keyLike = await this.importPublicKey(key, alg);
      } else {
        // Assume it's a symmetric key
        keyLike = new TextEncoder().encode(key) as unknown as KeyLike;
      }
    } else if (typeof key === 'object' && !('type' in key)) {
      // Assume it's a JWK
      keyLike = await this.importJWK(key as Record<string, unknown>, alg);
    } else {
      keyLike = key as KeyLike;
    }

    return {
      key: keyLike,
      alg,
      ...(kid !== undefined && { kid }),
    };
  }

  /**
   * Create a symmetric signing key
   */
  static createSymmetricKey(
    secret: string,
    alg: Algorithm = Algorithm.HS256,
    kid?: string,
  ): SigningKey {
    return {
      key: new TextEncoder().encode(secret) as unknown as KeyLike,
      alg,
      ...(kid !== undefined && { kid }),
    };
  }
}

/**
 * Default key manager instance
 */
export const defaultKeyManager = new KeyManager();
