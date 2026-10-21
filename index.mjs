import { createPublicKey, generateKeyPairSync, diffieHellman, hkdfSync, randomBytes, createCipheriv } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const recipient = Object.freeze(JSON.parse(readFileSync(new URL('./recipient.json', import.meta.url), 'utf8')));
export const prefix = 'alienmode://crypt5/';
export const salt = Buffer.from('AlienMode crypt5 v1', 'utf8');
export const maxInputBytes = 24576;
const spkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');

export function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).some(k => !['url', 'title'].includes(k))) throw new Error('invalid_input');
  const { url, title } = input;
  if (typeof url !== 'string' || Buffer.byteLength(url) > 16384 ||
      !/^https:\/\/[^/]/.test(url) || /[\s\u0000-\u001f\u007f\\]/u.test(url)) throw new Error('https_url_required');
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('invalid_url'); }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password ||
      parsed.port === '0' || url.slice(8).split(/[/?#]/, 1)[0].includes('@')) throw new Error('invalid_url');
  if (title !== undefined && (typeof title !== 'string' || [...title].length > 200 ||
      /[\u0000-\u001f\u007f]/u.test(title))) throw new Error('invalid_title');
  return { v: 1, url, ...(title?.trim() ? { title: title.trim() } : {}) };
}

// No provider secrets or decryption keys are needed to issue a link.
// This is an encrypted envelope, NOT proof of provider identity or entitlement.
export function encryptLink(input) {
  const payload = Buffer.from(JSON.stringify(validateInput(input)), 'utf8');
  const publicKey = createPublicKey({ key: Buffer.concat([spkiPrefix, Buffer.from(recipient.publicKey, 'base64url')]), format: 'der', type: 'spki' });
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralBytes = ephemeral.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const context = Buffer.from(prefix + recipient.kid, 'utf8');
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey });
  const key = Buffer.from(hkdfSync('sha256', shared, salt, context, 32));
  const nonce = randomBytes(12);
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.concat([context, ephemeralBytes]));
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const wire = Buffer.concat([ephemeralBytes, nonce, ciphertext, cipher.getAuthTag()]);
  shared.fill(0); key.fill(0); payload.fill(0);
  return prefix + recipient.kid + '.' + wire.toString('base64url');
}
