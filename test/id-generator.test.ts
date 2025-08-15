/**
 * Tests for ID Generators
 */

import {
  UuidGenerator,
  TimestampGenerator,
  PrefixedGenerator,
  CustomGenerator,
  defaultIdGenerator,
} from '../src/id/generator';

describe('ID Generators', () => {
  describe('UuidGenerator', () => {
    it('should generate valid UUID v4', () => {
      const generator = new UuidGenerator();
      const id = generator.generate();

      // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    it('should generate unique IDs', () => {
      const generator = new UuidGenerator();
      const ids = new Set();

      for (let i = 0; i < 100; i++) {
        ids.add(generator.generate());
      }

      expect(ids.size).toBe(100);
    });
  });

  describe('TimestampGenerator', () => {
    it('should generate timestamp-based IDs', () => {
      const generator = new TimestampGenerator();
      const id = generator.generate();

      expect(id).toMatch(/^\d+-\d+$/);
    });

    it('should increment counter for same timestamp', () => {
      const generator = new TimestampGenerator();
      const id1 = generator.generate();
      const id2 = generator.generate();

      const [, counter1] = id1.split('-');
      const [, counter2] = id2.split('-');

      expect(parseInt(counter2)).toBe(parseInt(counter1) + 1);
    });

    it('should generate unique IDs even in rapid succession', () => {
      const generator = new TimestampGenerator();
      const ids = new Set();

      for (let i = 0; i < 100; i++) {
        ids.add(generator.generate());
      }

      expect(ids.size).toBe(100);
    });
  });

  describe('PrefixedGenerator', () => {
    it('should add prefix to generated IDs', () => {
      const baseGenerator = new UuidGenerator();
      const generator = new PrefixedGenerator('test', baseGenerator);
      const id = generator.generate();

      expect(id).toMatch(
        /^test-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it('should use default UUID generator if none provided', () => {
      const generator = new PrefixedGenerator('evt');
      const id = generator.generate();

      expect(id).toMatch(
        /^evt-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it('should work with different base generators', () => {
      const timestampGen = new TimestampGenerator();
      const generator = new PrefixedGenerator('ts', timestampGen);
      const id = generator.generate();

      expect(id).toMatch(/^ts-\d+-\d+$/);
    });
  });

  describe('CustomGenerator', () => {
    it('should use custom function for ID generation', () => {
      let counter = 0;
      const generator = new CustomGenerator(() => `custom-${++counter}`);

      expect(generator.generate()).toBe('custom-1');
      expect(generator.generate()).toBe('custom-2');
      expect(generator.generate()).toBe('custom-3');
    });

    it('should handle complex custom functions', () => {
      const generator = new CustomGenerator(() => {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(7);
        return `${timestamp}-${random}`;
      });

      const id = generator.generate();
      expect(id).toMatch(/^\d+-[a-z0-9]+$/);
    });
  });

  describe('defaultIdGenerator', () => {
    it('should be an instance of UuidGenerator', () => {
      expect(defaultIdGenerator).toBeInstanceOf(UuidGenerator);
    });

    it('should generate valid UUIDs', () => {
      const id = defaultIdGenerator.generate();
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });
  });
});
