// Secrets (authenticator keys, and later OAuth tokens and agency API keys) never go in the
// database. The database stores only a reference and, where useful, a display hint.
//
// LocalEncryptedStore: AES-256-GCM in a local file, for development.
// Production: swap for AWS Secrets Manager (same interface).
import { randomBytes, createCipheriv, createDecipheriv, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

export interface SecretStore {
  put(value: string): string;          // returns a reference
  get(ref: string): string;
}

export class LocalEncryptedStore implements SecretStore {
  private key: Buffer;
  private file: string;
  constructor(file: string, keyHex: string) {
    this.file = file;
    if (!/^[0-9a-f]{64}$/i.test(keyHex)) throw new Error('SECRETS_KEY must be 32 bytes as 64 hex characters');
    this.key = Buffer.from(keyHex, 'hex');
  }
  private load(): Record<string, string> {
    return existsSync(this.file) ? JSON.parse(readFileSync(this.file, 'utf8')) : {};
  }
  put(value: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const enc = Buffer.concat([c.update(value, 'utf8'), c.final()]);
    const blob = Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
    const ref = `local:${randomUUID()}`;
    const all = this.load();
    all[ref] = blob;
    writeFileSync(this.file, JSON.stringify(all), { mode: 0o600 });
    return ref;
  }
  get(ref: string): string {
    const blob = this.load()[ref];
    if (!blob) throw new Error(`unknown secret ${ref}`);
    const buf = Buffer.from(blob, 'base64');
    const d = createDecipheriv('aes-256-gcm', this.key, buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
  }
}

export const hint = (secret: string) => `••••${secret.slice(-4)}`;
