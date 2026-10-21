#!/usr/bin/env node
import { encryptLink, maxInputBytes } from './index.mjs';

// Read secrets from stdin, never from argv (shell history / process listings).
try {
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > maxInputBytes) throw new Error('input_too_large');
    chunks.push(chunk);
  }
  process.stdout.write(JSON.stringify({ link: encryptLink(JSON.parse(Buffer.concat(chunks).toString('utf8'))) }) + '\n');
} catch {
  process.stderr.write('Cannot generate link: provide JSON with a valid HTTPS url and optional title via stdin.\n');
  process.exitCode = 1;
}
