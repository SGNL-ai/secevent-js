/**
 * Tests for Signing utilities
 */

import {
  KeyManager,
  SigningUtils,
  Algorithm,
  defaultKeyManager,
} from '../src/signing/signer';

describe('Signing', () => {
  describe('KeyManager', () => {
    let keyManager: KeyManager;

    beforeEach(() => {
      keyManager = new KeyManager();
    });

    it('should add and retrieve keys', () => {
      const key = {
        key: 'test-key',
        alg: Algorithm.HS256,
      };

      keyManager.addKey('key1', key);
      const retrieved = keyManager.getKey('key1');

      expect(retrieved).toBeDefined();
      expect(retrieved?.kid).toBe('key1');
      expect(retrieved?.alg).toBe(Algorithm.HS256);
    });

    it('should get all keys', () => {
      const key1 = { key: 'key1', alg: Algorithm.HS256 };
      const key2 = { key: 'key2', alg: Algorithm.RS256 };

      keyManager.addKey('id1', key1);
      keyManager.addKey('id2', key2);

      const allKeys = keyManager.getAllKeys();
      expect(allKeys).toHaveLength(2);
      expect(allKeys[0]?.kid).toBe('id1');
      expect(allKeys[1]?.kid).toBe('id2');
    });

    it('should remove keys', () => {
      const key = { key: 'test', alg: Algorithm.HS256 };
      keyManager.addKey('key1', key);

      expect(keyManager.removeKey('key1')).toBe(true);
      expect(keyManager.getKey('key1')).toBeUndefined();
      expect(keyManager.removeKey('key1')).toBe(false);
    });

    it('should clear all keys', () => {
      keyManager.addKey('key1', { key: 'test1', alg: Algorithm.HS256 });
      keyManager.addKey('key2', { key: 'test2', alg: Algorithm.HS256 });

      keyManager.clear();
      expect(keyManager.getAllKeys()).toHaveLength(0);
    });

    it('should get default key (first added)', () => {
      expect(keyManager.getDefaultKey()).toBeUndefined();

      keyManager.addKey('key1', { key: 'test1', alg: Algorithm.HS256 });
      keyManager.addKey('key2', { key: 'test2', alg: Algorithm.RS256 });

      const defaultKey = keyManager.getDefaultKey();
      expect(defaultKey?.kid).toBe('key1');
    });

    it('should handle empty key manager', () => {
      expect(keyManager.getDefaultKey()).toBeUndefined();
      expect(keyManager.getAllKeys()).toHaveLength(0);
      expect(keyManager.getKey('nonexistent')).toBeUndefined();
    });
  });

  describe('SigningUtils', () => {
    describe('generateKeyPair', () => {
      it('should generate RSA key pair', async () => {
        const { publicKey, privateKey } = await SigningUtils.generateKeyPair(Algorithm.RS256);
        
        expect(publicKey).toBeDefined();
        expect(privateKey).toBeDefined();
      });

      it('should generate key pair with custom options', async () => {
        const { publicKey, privateKey } = await SigningUtils.generateKeyPair(
          Algorithm.RS256,
          { modulusLength: 2048, extractable: true }
        );
        
        expect(publicKey).toBeDefined();
        expect(privateKey).toBeDefined();
      });

      it('should generate ES256 key pair', async () => {
        const { publicKey, privateKey } = await SigningUtils.generateKeyPair(Algorithm.ES256);
        
        expect(publicKey).toBeDefined();
        expect(privateKey).toBeDefined();
      });
    });

    describe('importJWK', () => {
      it('should import a JWK', async () => {
        const jwk = {
          kty: 'oct',
          k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
          alg: 'HS256',
        };

        const key = await SigningUtils.importJWK(jwk, Algorithm.HS256);
        expect(key).toBeDefined();
      });
    });

    describe('importPrivateKey', () => {
      it('should import a PKCS8 private key', async () => {
        // This is a test RSA private key in PKCS8 format
        const pkcs8 = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPhh3oltZODL1y
b8N8fMNu48vJCKaHhVJy5eWLrJJfSJilW4lxgoIuR8sZmYU/xAzkKVqKrnqaugHE
gS3mDmGjBgCCtHlaT+TcJhYWJIrk7aXCNDSVw5aBLWVJEazkAXzSDiGGixHPSHRz
sLvvvmPJ9cE6kUJqaVm4LKaGUZ6DomjLjBj7HhDvTfvTniVWmQl8LflrHohlGdMD
9wDcD9Ej6LgJJGwdTpbqfwP7HBOUxYmFpAtC3gvGaXbtQIMaF2tfT+0vLj7AMVvW
HJMvmBCCJW3CwIFTJNvFvYrGKLe5mLYjWjBRisJxQLqRkBk9mP1pFO/dEqx3lvcf
OlkNFQCnAgMBAAECggEAW3KvVMPVxs9TLvs0UUmDknKvLWjY+v/6N7jJ1CqpGFdm
EMYYLhJIQvRvNWlp3I9sg2b4an3yGPQ+yEx5E9V0Znpw/eoO7XdH/hShRnCcGGZx
i7uGWMdZ+bLM4t6FsHqrP/pFcT/eIGL3Pt1gGJRJRXLvPPLbQqLfWD9r3Q+dGH2H
3AUcnlEp2vPNxZbHj4XqPCvpCbCGQfg8DClQUlD4DH8Lhwj6xYRQ0l7EDoE8dJnz
LwjlUKdmZJqcZn/3fX4nBHO7O5P0O7EXlFEifgORFfGnK5kFNfzPUO2sFLJx9HQ8
wYE6glQsztnnn+ZHU1A5y1gVXTLYgFWF2bE8cPuYgQKBgQDyg1+t+6lqCqLZSmaT
DyH4J9sqHJQlBxUpJ3Gf8gLMPZWsPkUvQ7z0cgV28VPbuvqqLr8lS8M4Km+tnEAk
U7mrKcSNpnJRfN0ocjE6uCDF3UqwnqV/M0N5vomBHdIq7kYVjeDGLKzsgZZKFyF+
JBA8Z7zAO2SdTjGTW0+O8kv+BwKBgQDbCLIxMWYJBjzVpkqiAYz6Vvr5eFvUYvIS
/vgHYo70MsrLhKAJ9WM9VSpKaNVQU7TXjihJmYKdiTJlSJ7iz1RQdrQPdLKJs2Xl
tKHkwmF0Aa9rh7aD4qP3w9Tcp4oXvxhZe8BT2VKKgX6zfhv8gptLc2L9XVAT4zXF
FAXVNIszYQKBgAtDqZQfbQp4EdAiBqGJswvFYTWxsSQI9rIXoVmVFGmdLRupMmzH
1TlMipQRacE3PIhCQ8gFiDWt2cMq7nGgy5H8EE7Ki1bjNRRJDM8neXdlaKPzho8N
yZ7rKPbCgRHkkr6IhCgH2gYwYzMXGLWnKe0zrZOz4PCKLvG8I5F6eSOXAoGBAMJy
A4Yh6gbKQtr6Q41r7GOCktXM4hPXzhKVJuPTMAqwh3SXDB5/1S5KRevEV2hn1BYW
3WZ2cPYxxFR9p+9KzOW0m1wZ9n5k1p7sUx3KdAyxyZrzQndVvFuVPgPpLIde8deV
hx8JOPhXQ+T8PKBTCq8V8mO2taBYZjKSzL+qgQihAoGBAK7wbmQXfBpRRAGE14mP
vEFJe0bK9YWLFrM4uCsVqTmr0x1LT3taWqEEciStiPnRGe72VCpupT7LqYhmEy2L
r8bbfqGoLER3r3mJKdmfMObHXfohCq3wJRK5s3oEPnK0rVEqJZNq8vYd+KTmONRd
nI0hJnftu5WYG8srUlHVE/kA
-----END PRIVATE KEY-----`;

        const key = await SigningUtils.importPrivateKey(pkcs8, Algorithm.RS256);
        expect(key).toBeDefined();
      });

      it('should import with extractable option', async () => {
        const pkcs8 = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPhh3oltZODL1y
b8N8fMNu48vJCKaHhVJy5eWLrJJfSJilW4lxgoIuR8sZmYU/xAzkKVqKrnqaugHE
gS3mDmGjBgCCtHlaT+TcJhYWJIrk7aXCNDSVw5aBLWVJEazkAXzSDiGGixHPSHRz
sLvvvmPJ9cE6kUJqaVm4LKaGUZ6DomjLjBj7HhDvTfvTniVWmQl8LflrHohlGdMD
9wDcD9Ej6LgJJGwdTpbqfwP7HBOUxYmFpAtC3gvGaXbtQIMaF2tfT+0vLj7AMVvW
HJMvmBCCJW3CwIFTJNvFvYrGKLe5mLYjWjBRisJxQLqRkBk9mP1pFO/dEqx3lvcf
OlkNFQCnAgMBAAECggEAW3KvVMPVxs9TLvs0UUmDknKvLWjY+v/6N7jJ1CqpGFdm
EMYYLhJIQvRvNWlp3I9sg2b4an3yGPQ+yEx5E9V0Znpw/eoO7XdH/hShRnCcGGZx
i7uGWMdZ+bLM4t6FsHqrP/pFcT/eIGL3Pt1gGJRJRXLvPPLbQqLfWD9r3Q+dGH2H
3AUcnlEp2vPNxZbHj4XqPCvpCbCGQfg8DClQUlD4DH8Lhwj6xYRQ0l7EDoE8dJnz
LwjlUKdmZJqcZn/3fX4nBHO7O5P0O7EXlFEifgORFfGnK5kFNfzPUO2sFLJx9HQ8
wYE6glQsztnnn+ZHU1A5y1gVXTLYgFWF2bE8cPuYgQKBgQDyg1+t+6lqCqLZSmaT
DyH4J9sqHJQlBxUpJ3Gf8gLMPZWsPkUvQ7z0cgV28VPbuvqqLr8lS8M4Km+tnEAk
U7mrKcSNpnJRfN0ocjE6uCDF3UqwnqV/M0N5vomBHdIq7kYVjeDGLKzsgZZKFyF+
JBA8Z7zAO2SdTjGTW0+O8kv+BwKBgQDbCLIxMWYJBjzVpkqiAYz6Vvr5eFvUYvIS
/vgHYo70MsrLhKAJ9WM9VSpKaNVQU7TXjihJmYKdiTJlSJ7iz1RQdrQPdLKJs2Xl
tKHkwmF0Aa9rh7aD4qP3w9Tcp4oXvxhZe8BT2VKKgX6zfhv8gptLc2L9XVAT4zXF
FAXVNIszYQKBgAtDqZQfbQp4EdAiBqGJswvFYTWxsSQI9rIXoVmVFGmdLRupMmzH
1TlMipQRacE3PIhCQ8gFiDWt2cMq7nGgy5H8EE7Ki1bjNRRJDM8neXdlaKPzho8N
yZ7rKPbCgRHkkr6IhCgH2gYwYzMXGLWnKe0zrZOz4PCKLvG8I5F6eSOXAoGBAMJy
A4Yh6gbKQtr6Q41r7GOCktXM4hPXzhKVJuPTMAqwh3SXDB5/1S5KRevEV2hn1BYW
3WZ2cPYxxFR9p+9KzOW0m1wZ9n5k1p7sUx3KdAyxyZrzQndVvFuVPgPpLIde8deV
hx8JOPhXQ+T8PKBTCq8V8mO2taBYZjKSzL+qgQihAoGBAK7wbmQXfBpRRAGE14mP
vEFJe0bK9YWLFrM4uCsVqTmr0x1LT3taWqEEciStiPnRGe72VCpupT7LqYhmEy2L
r8bbfqGoLER3r3mJKdmfMObHXfohCq3wJRK5s3oEPnK0rVEqJZNq8vYd+KTmONRd
nI0hJnftu5WYG8srUlHVE/kA
-----END PRIVATE KEY-----`;

        const key = await SigningUtils.importPrivateKey(pkcs8, Algorithm.RS256, { extractable: true });
        expect(key).toBeDefined();
      });
    });

    describe('importPublicKey', () => {
      it('should import a SPKI public key', async () => {
        const spki = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz4Yd6JbWTgy9cm/DfHzD
buPLyQimh4VScuXli6ySX0iYpVuJcYKCLkfLGZmFP8QM5Claiuq5q6mroBxIEt5g
4xqgYAgrR5Wk/k3CYWFiSK5O2lwjQ0lcOWgS1lSRGs5AF80g4hhosRz0h0c7C77
75j5yfXBOpFCamlZuCymhlGeg6Jpyy4wY+x4Q70370p54lVlpkJfC35ax6IZRnTA
/cA3A/RI+i4CSRsHU6W6n8D+xwTlMWJhaQLQt4Lxmm27UCDGRZ29L7S8uPsDZX1
scm+YEIIlbcLAUyTbxb2Kxii3uZi2I1owUYrCcUC6kZAZPZj9aRTv3RKsd5b3HzpZ
DRUApwIDAQAB
-----END PUBLIC KEY-----`;

        const key = await SigningUtils.importPublicKey(spki, Algorithm.RS256);
        expect(key).toBeDefined();
      });

      it('should import with extractable option', async () => {
        const spki = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz4Yd6JbWTgy9cm/DfHzD
buPLyQimh4VScuXli6ySX0iYpVuJcYKCLkfLGZmFP8QM5Claiuq5q6mroBxIEt5g
4xqgYAgrR5Wk/k3CYWFiSK5O2lwjQ0lcOWgS1lSRGs5AF80g4hhosRz0h0c7C77
75j5yfXBOpFCamlZuCymhlGeg6Jpyy4wY+x4Q70370p54lVlpkJfC35ax6IZRnTA
/cA3A/RI+i4CSRsHU6W6n8D+xwTlMWJhaQLQt4Lxmm27UCDGRZ29L7S8uPsDZX1
scm+YEIIlbcLAUyTbxb2Kxii3uZi2I1owUYrCcUC6kZAZPZj9aRTv3RKsd5b3HzpZ
DRUApwIDAQAB
-----END PUBLIC KEY-----`;

        const key = await SigningUtils.importPublicKey(spki, Algorithm.RS256, { extractable: true });
        expect(key).toBeDefined();
      });
    });

    describe('createSigningKey', () => {
      it('should create signing key from PEM private key', async () => {
        const pem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPhh3oltZODL1y
b8N8fMNu48vJCKaHhVJy5eWLrJJfSJilW4lxgoIuR8sZmYU/xAzkKVqKrnqaugHE
gS3mDmGjBgCCtHlaT+TcJhYWJIrk7aXCNDSVw5aBLWVJEazkAXzSDiGGixHPSHRz
sLvvvmPJ9cE6kUJqaVm4LKaGUZ6DomjLjBj7HhDvTfvTniVWmQl8LflrHohlGdMD
9wDcD9Ej6LgJJGwdTpbqfwP7HBOUxYmFpAtC3gvGaXbtQIMaF2tfT+0vLj7AMVvW
HJMvmBCCJW3CwIFTJNvFvYrGKLe5mLYjWjBRisJxQLqRkBk9mP1pFO/dEqx3lvcf
OlkNFQCnAgMBAAECggEAW3KvVMPVxs9TLvs0UUmDknKvLWjY+v/6N7jJ1CqpGFdm
EMYYLhJIQvRvNWlp3I9sg2b4an3yGPQ+yEx5E9V0Znpw/eoO7XdH/hShRnCcGGZx
i7uGWMdZ+bLM4t6FsHqrP/pFcT/eIGL3Pt1gGJRJRXLvPPLbQqLfWD9r3Q+dGH2H
3AUcnlEp2vPNxZbHj4XqPCvpCbCGQfg8DClQUlD4DH8Lhwj6xYRQ0l7EDoE8dJnz
LwjlUKdmZJqcZn/3fX4nBHO7O5P0O7EXlFEifgORFfGnK5kFNfzPUO2sFLJx9HQ8
wYE6glQsztnnn+ZHU1A5y1gVXTLYgFWF2bE8cPuYgQKBgQDyg1+t+6lqCqLZSmaT
DyH4J9sqHJQlBxUpJ3Gf8gLMPZWsPkUvQ7z0cgV28VPbuvqqLr8lS8M4Km+tnEAk
U7mrKcSNpnJRfN0ocjE6uCDF3UqwnqV/M0N5vomBHdIq7kYVjeDGLKzsgZZKFyF+
JBA8Z7zAO2SdTjGTW0+O8kv+BwKBgQDbCLIxMWYJBjzVpkqiAYz6Vvr5eFvUYvIS
/vgHYo70MsrLhKAJ9WM9VSpKaNVQU7TXjihJmYKdiTJlSJ7iz1RQdrQPdLKJs2Xl
tKHkwmF0Aa9rh7aD4qP3w9Tcp4oXvxhZe8BT2VKKgX6zfhv8gptLc2L9XVAT4zXF
FAXVNIszYQKBgAtDqZQfbQp4EdAiBqGJswvFYTWxsSQI9rIXoVmVFGmdLRupMmzH
1TlMipQRacE3PIhCQ8gFiDWt2cMq7nGgy5H8EE7Ki1bjNRRJDM8neXdlaKPzho8N
yZ7rKPbCgRHkkr6IhCgH2gYwYzMXGLWnKe0zrZOz4PCKLvG8I5F6eSOXAoGBAMJy
A4Yh6gbKQtr6Q41r7GOCktXM4hPXzhKVJuPTMAqwh3SXDB5/1S5KRevEV2hn1BYW
3WZ2cPYxxFR9p+9KzOW0m1wZ9n5k1p7sUx3KdAyxyZrzQndVvFuVPgPpLIde8deV
hx8JOPhXQ+T8PKBTCq8V8mO2taBYZjKSzL+qgQihAoGBAK7wbmQXfBpRRAGE14mP
vEFJe0bK9YWLFrM4uCsVqTmr0x1LT3taWqEEciStiPnRGe72VCpupT7LqYhmEy2L
r8bbfqGoLER3r3mJKdmfMObHXfohCq3wJRK5s3oEPnK0rVEqJZNq8vYd+KTmONRd
nI0hJnftu5WYG8srUlHVE/kA
-----END PRIVATE KEY-----`;

        const signingKey = await SigningUtils.createSigningKey(pem, Algorithm.RS256, 'test-key');
        
        expect(signingKey.key).toBeDefined();
        expect(signingKey.alg).toBe(Algorithm.RS256);
        expect(signingKey.kid).toBe('test-key');
      });

      it('should create signing key from PEM public key', async () => {
        const pem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz4Yd6JbWTgy9cm/DfHzD
buPLyQimh4VScuXli6ySX0iYpVuJcYKCLkfLGZmFP8QM5Claiuq5q6mroBxIEt5g
4xqgYAgrR5Wk/k3CYWFiSK5O2lwjQ0lcOWgS1lSRGs5AF80g4hhosRz0h0c7C77
75j5yfXBOpFCamlZuCymhlGeg6Jpyy4wY+x4Q70370p54lVlpkJfC35ax6IZRnTA
/cA3A/RI+i4CSRsHU6W6n8D+xwTlMWJhaQLQt4Lxmm27UCDGRZ29L7S8uPsDZX1
scm+YEIIlbcLAUyTbxb2Kxii3uZi2I1owUYrCcUC6kZAZPZj9aRTv3RKsd5b3HzpZ
DRUApwIDAQAB
-----END PUBLIC KEY-----`;

        const signingKey = await SigningUtils.createSigningKey(pem, Algorithm.RS256);
        
        expect(signingKey.key).toBeDefined();
        expect(signingKey.alg).toBe(Algorithm.RS256);
        expect(signingKey.kid).toBeUndefined();
      });

      it('should create signing key from symmetric key string', async () => {
        const signingKey = await SigningUtils.createSigningKey('my-secret-key', Algorithm.HS256, 'symmetric-key');
        
        expect(signingKey.key).toBeDefined();
        expect(signingKey.alg).toBe(Algorithm.HS256);
        expect(signingKey.kid).toBe('symmetric-key');
      });

      it('should create signing key from JWK', async () => {
        const jwk = {
          kty: 'oct',
          k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
          alg: 'HS256',
        };

        const signingKey = await SigningUtils.createSigningKey(jwk, Algorithm.HS256, 'jwk-key');
        
        expect(signingKey.key).toBeDefined();
        expect(signingKey.alg).toBe(Algorithm.HS256);
        expect(signingKey.kid).toBe('jwk-key');
      });

      it('should pass through KeyLike object', async () => {
        const { privateKey } = await SigningUtils.generateKeyPair(Algorithm.RS256);
        
        const signingKey = await SigningUtils.createSigningKey(privateKey, Algorithm.RS256);
        
        expect(signingKey.key).toBe(privateKey);
        expect(signingKey.alg).toBe(Algorithm.RS256);
      });
    });

    describe('createSymmetricKey', () => {
      it('should create symmetric key with default algorithm', () => {
        const key = SigningUtils.createSymmetricKey('secret');
        
        expect(key.key).toBeDefined();
        expect(key.alg).toBe(Algorithm.HS256);
        expect(key.kid).toBeUndefined();
      });

      it('should create symmetric key with custom algorithm and kid', () => {
        const key = SigningUtils.createSymmetricKey('secret', Algorithm.HS384, 'my-key');
        
        expect(key.key).toBeDefined();
        expect(key.alg).toBe(Algorithm.HS384);
        expect(key.kid).toBe('my-key');
      });

      it('should create different keys for HS256, HS384, HS512', () => {
        const key256 = SigningUtils.createSymmetricKey('secret', Algorithm.HS256);
        const key384 = SigningUtils.createSymmetricKey('secret', Algorithm.HS384);
        const key512 = SigningUtils.createSymmetricKey('secret', Algorithm.HS512);
        
        expect(key256.alg).toBe(Algorithm.HS256);
        expect(key384.alg).toBe(Algorithm.HS384);
        expect(key512.alg).toBe(Algorithm.HS512);
      });
    });
  });

  describe('defaultKeyManager', () => {
    it('should be a KeyManager instance', () => {
      expect(defaultKeyManager).toBeInstanceOf(KeyManager);
    });

    it('should start empty', () => {
      // Clear any existing keys first
      defaultKeyManager.clear();
      expect(defaultKeyManager.getAllKeys()).toHaveLength(0);
    });
  });

  describe('Algorithm enum', () => {
    it('should have all supported algorithms', () => {
      expect(Algorithm.RS256).toBe('RS256');
      expect(Algorithm.RS384).toBe('RS384');
      expect(Algorithm.RS512).toBe('RS512');
      expect(Algorithm.PS256).toBe('PS256');
      expect(Algorithm.PS384).toBe('PS384');
      expect(Algorithm.PS512).toBe('PS512');
      expect(Algorithm.ES256).toBe('ES256');
      expect(Algorithm.ES384).toBe('ES384');
      expect(Algorithm.ES512).toBe('ES512');
      expect(Algorithm.HS256).toBe('HS256');
      expect(Algorithm.HS384).toBe('HS384');
      expect(Algorithm.HS512).toBe('HS512');
    });
  });
});