/** Fix one original write intent with the production SDK; no network is used. */
import { readFileSync } from 'node:fs';
import { Client } from '../../sdk/node/src/client.js';

const input = JSON.parse(readFileSync(0, 'utf8'));
const client = new Client({ endpoint: 'http://127.0.0.1:1/v1', allowInsecureHttp: true,
  token: 'r'.repeat(64), scope: input.scope, principal: '11' });
const intent = client.prepare([{ sql: input.sql, parameters: [] }], { epoch: '1', id: '1' });
process.stdout.write(client.save(intent) + '\n');
