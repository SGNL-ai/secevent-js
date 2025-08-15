/**
 * ID Generators for Security Event Tokens
 */

import { v4 as uuidv4 } from 'uuid';
import { IdGenerator } from '../types/secevent';

/**
 * UUID v4 ID generator
 */
export class UuidGenerator implements IdGenerator {
  generate(): string {
    return uuidv4();
  }
}

/**
 * Timestamp-based ID generator
 */
export class TimestampGenerator implements IdGenerator {
  private counter = 0;

  generate(): string {
    const timestamp = Date.now();
    const count = this.counter++;
    return `${timestamp}-${count}`;
  }
}

/**
 * Prefixed ID generator
 */
export class PrefixedGenerator implements IdGenerator {
  constructor(
    private prefix: string,
    private baseGenerator: IdGenerator = new UuidGenerator(),
  ) {}

  generate(): string {
    return `${this.prefix}-${this.baseGenerator.generate()}`;
  }
}

/**
 * Custom function-based ID generator
 */
export class CustomGenerator implements IdGenerator {
  constructor(private generatorFn: () => string) {}

  generate(): string {
    return this.generatorFn();
  }
}

/**
 * Default ID generator
 */
export const defaultIdGenerator = new UuidGenerator();
