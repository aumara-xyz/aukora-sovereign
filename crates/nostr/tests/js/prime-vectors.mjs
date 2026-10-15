// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable fixed keys and deterministic randomness are only for vector generation.
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';
import { writeFileSync } from 'node:fs';

const prime = process.argv[2] ?? '/Users/peterviviani/aukora-prime';
let counter = 32;
const random = length => Buffer.alloc(length, counter++);
crypto.randomBytes = random;
syncBuiltinESMExports();
Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
  getRandomValues(bytes) { bytes.set(random(bytes.length)); return bytes; },
} });
const load = file => import(pathToFileURL(`${prime}/plugins/aukora-nostr/lib/${file}`).href);
const event = await load('event.mjs');
const nip44 = await load('nip44.mjs');
const gift = await load('giftwrap.mjs');
const identity = await load('identity.mjs');

const sender = '01'.padStart(64, '0');
const recipient = '02'.padStart(64, '0');
const ephemeral = '03'.padStart(64, '0');
const senderPubkey = event.publicKeyOf(sender);
const recipientPubkey = event.publicKeyOf(recipient);
const template = { pubkey: senderPubkey, created_at: 1700000000, kind: 1,
  tags: [['p', recipientPubkey], ['text', '雪\n"\\\r\t\b\f']], content: 'Hello 雪\n"\\\r\t\b\f\u2028\u2029' };
const signed = event.signEvent(structuredClone(template), sender);
const nonce = Buffer.alloc(32, 12);
const plaintext = 'Prime → Sovereign: 雪';
const conversationKey = nip44.conversationKey(sender, Buffer.from(recipientPubkey, 'hex'));
const payload = nip44.encrypt(plaintext, conversationKey, nonce);
const rumor = gift.createRumor({ kind: 14, content: 'A private cross-implementation message',
  tags: [['p', recipientPubkey]], secretKey: sender, createdAt: 1700000000 });
const seal = gift.sealRumor(rumor, { senderSecretKey: sender, recipientPubkey, createdAt: 1699999990 });
const wrap = gift.wrapEvent(seal, { recipientPubkey, ephemeralSecretKey: ephemeral, createdAt: 1699999980 });
const opened = gift.openGiftWrap(wrap, { recipientSecretKey: recipient });
if (JSON.stringify(opened.rumor) !== JSON.stringify(rumor)) throw new Error('Prime self-check failed');
const vectors = { schema: 'aukora-nostr-prime-vectors-v1', source: 'aukora-prime/plugins/aukora-nostr/lib',
  sender_secret_fixture: sender, recipient_secret_fixture: recipient, ephemeral_secret_fixture: ephemeral,
  public_keys: [sender, recipient, ephemeral].map(secret => {
    const pubkey = event.publicKeyOf(secret);
    return { pubkey, npub: identity.npubEncode(pubkey) };
  }), event: signed, serialized_event: event.serializeForId(template),
  nip44: { plaintext, nonce: nonce.toString('hex'), conversation_key: conversationKey.toString('hex'), payload },
  rumor, seal, wrap };
writeFileSync(new URL('../vectors/prime-vectors.json', import.meta.url), `${JSON.stringify(vectors, null, 2)}\n`);
console.log('Prime vectors: event, 3 npubs, NIP-44 payload, rumor, seal, gift wrap verified');
