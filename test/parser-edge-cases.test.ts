/**
 * Edge case tests for parser to achieve 100% coverage
 */

import { SecEventParser } from '../src/parser/parser';
import { SigningUtils, Algorithm } from '../src/signing/signer';
import { SignJWT } from 'jose';

describe('Parser Edge Cases', () => {
  describe('JWKS verification path', () => {
    it('should handle successful JWKS verification', async () => {
      // Mock the JWKS module properly
      const mockJwks = jest.fn().mockResolvedValue({
        payload: {
          iss: 'https://example.com',
          jti: 'test-123',
          iat: Math.floor(Date.now() / 1000),
          events: {
            'https://example.com/event': { data: 'test' }
          }
        },
        protectedHeader: {}
      });

      const parser = new SecEventParser({ jwksUrl: 'https://example.com/.well-known/jwks.json' });
      
      // Override the jwks property
      (parser as any).jwks = mockJwks;

      const result = await parser.verify('dummy.jwt.token');
      
      expect(result.valid).toBe(true);
      expect(result.payload?.iss).toBe('https://example.com');
    });

    it('should handle no verification method error correctly', async () => {
      const parser = new SecEventParser();
      
      // Try to verify without providing key or having JWKS
      const result = await parser.verify('dummy.jwt.token');
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('No verification key or JWKS URL provided');
    });
  });

  describe('validateSecEvent edge cases', () => {
    it('should handle non-Error exception in validatePayloadStructure', () => {
      const parser = new SecEventParser();
      
      // Mock validatePayloadStructure to throw a non-Error
      jest.spyOn(parser as any, 'validatePayloadStructure').mockImplementation(() => {
        throw 'String error';
      });

      const errors = (parser as any).validateSecEvent(
        { iss: 'test', jti: '123', iat: 123, events: {} },
        {}
      );

      expect(errors).toContain('Invalid payload structure');
    });

    it('should validate payload with empty events object', () => {
      const parser = new SecEventParser();
      
      const payload = {
        iss: 'test',
        jti: '123',
        iat: Math.floor(Date.now() / 1000),
        events: {}
      };

      const errors = (parser as any).validateSecEvent(payload, {});
      
      expect(errors).toContain('No events present in events claim');
    });
  });

  describe('Algorithm defaults', () => {
    it('should use default algorithm for generateKeyPair', async () => {
      // Call without specifying algorithm
      const { publicKey, privateKey } = await SigningUtils.generateKeyPair();
      
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
    });
  });
});