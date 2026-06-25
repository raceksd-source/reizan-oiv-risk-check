import test from 'node:test';
import assert from 'node:assert/strict';

import { assessDomain, buildRiskCheckReport, normalizeDomain, scoreSignals } from '../src/index.js';
import type { DnsClient, HttpClient, HttpResponse, MxRecord } from '../src/index.js';
import { parseCliArgs } from '../src/cli.js';
import { resolveOivContext } from '../src/oiv.js';

class MockDns implements DnsClient {
  constructor(
    private readonly txt = new Map<string, string[]>(),
    private readonly mx = new Map<string, MxRecord[]>(),
    private readonly generic = new Map<string, unknown[]>()
  ) {}

  async resolveTxt(hostname: string): Promise<string[][]> {
    const records = this.txt.get(hostname);
    if (records === undefined) {
      throw dnsError('ENODATA');
    }

    return records.map((record) => [record]);
  }

  async resolveMx(hostname: string): Promise<MxRecord[]> {
    const records = this.mx.get(hostname);
    if (records === undefined) {
      throw dnsError('ENODATA');
    }

    return records;
  }

  async resolve(hostname: string, rrtype: string): Promise<unknown[]> {
    const key = `${rrtype}:${hostname}`;
    const records = this.generic.get(key);
    if (records === undefined) {
      return [];
    }

    return records;
  }
}

void test('normalizeDomain accepts URLs and rejects IP addresses', () => {
  assert.equal(normalizeDomain('https://Example.CL/path'), 'example.cl');
  assert.throws(() => normalizeDomain('127.0.0.1'), /domain name/);
});

void test('assessDomain collects passive signals and reaches a mature score', async () => {
  const dns = new MockDns(
    new Map([
      ['example.cl', ['v=spf1 include:_spf.example.cl -all']],
      ['_dmarc.example.cl', ['v=DMARC1; p=reject; rua=mailto:dmarc@example.cl']],
      ['selector1._domainkey.example.cl', ['v=DKIM1; k=rsa; p=abc']],
      ['_mta-sts.example.cl', ['v=STSv1; id=20260625']]
    ]),
    new Map([
      [
        'example.cl',
        [
          { exchange: 'mx1.example.cl', priority: 10 },
          { exchange: 'mx2.example.cl', priority: 20 }
        ]
      ]
    ]),
    new Map([
      ['DS:example.cl', [{ keyTag: 1 }]],
      ['DNSKEY:example.cl', [{ flags: 257 }]]
    ])
  );
  const http = mockHttp({
    'HEAD https://example.cl/': response('', 200, { 'strict-transport-security': 'max-age=31536000' }),
    'GET https://mta-sts.example.cl/.well-known/mta-sts.txt': response('version: STSv1\nmode: enforce\nmx: mx1.example.cl\nmax_age: 86400\n')
  });

  const signals = await assessDomain('example.cl', {
    dnsClient: dns,
    httpClient: http,
    dkimSelectors: ['selector1'],
    timeoutMs: 1_000
  });

  assert.equal(signals.spf.allMechanism, '-all');
  assert.equal(signals.dmarc.policy, 'reject');
  assert.deepEqual(signals.dkim.selectorsFound, ['selector1']);
  assert.equal(signals.mtaSts.policyMode, 'enforce');
  assert.equal(signals.https.hsts, true);
  assert.equal(scoreSignals(signals).total, 100);
});

void test('buildRiskCheckReport refuses domain assessment without self-attestation', async () => {
  await assert.rejects(
    () => buildRiskCheckReport({ domain: 'example.cl', selfAttested: false }),
    /self-attest/
  );
});

void test('CLI parser supports required flags and selector override', () => {
  const parsed = parseCliArgs([
    '--domain=example.cl',
    '--rut',
    '97006000-6',
    '--self-attest',
    '--dkim-selectors',
    'selector1,selector2',
    '--json'
  ]);

  assert.equal(parsed.domain, 'example.cl');
  assert.equal(parsed.rut, '97006000-6');
  assert.equal(parsed.selfAttested, true);
  assert.equal(parsed.json, true);
  assert.deepEqual(parsed.dkimSelectors, ['selector1', 'selector2']);
});

void test('OIV lookup uses anci-oiv-resolver table without requiring DNS', async () => {
  const context = await resolveOivContext({ rut: '97006000-6' });

  assert.equal(context.designated, true);
  assert.equal(context.sector, 'banca_finanzas');
  assert.equal(context.fase, null);
  assert.match(context.faseSource, /does not publish a FASE field/);
});

function dnsError(code: string): Error {
  const error = new Error(code) as Error & { code: string };
  error.code = code;
  return error;
}

function mockHttp(routes: Record<string, HttpResponse>): HttpClient {
  return async (input, init) => {
    const key = `${init.method ?? 'GET'} ${input}`;
    const found = routes[key];
    if (found === undefined) {
      throw new Error(`No mock route for ${key}`);
    }

    return found;
  };
}

function response(body: string, status = 200, headers: Record<string, string> = {}): HttpResponse {
  const normalizedHeaders = new Map(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));

  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return body;
    },
    headers: {
      get(name: string) {
        return normalizedHeaders.get(name.toLowerCase()) ?? null;
      }
    }
  };
}
