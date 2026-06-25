import { promises as dns } from 'node:dns';
import { domainToASCII } from 'node:url';

import type {
  AssessmentOptions,
  DkimSignal,
  DmarcPolicy,
  DmarcSignal,
  DnsClient,
  DnssecSignal,
  DomainSignals,
  HttpClient,
  HttpsSignal,
  MtaStsMode,
  MtaStsSignal,
  MxRecord,
  MxSignal,
  SpfSignal
} from './types.js';

export const DEFAULT_DKIM_SELECTORS = [
  'default',
  'selector1',
  'selector2',
  'google',
  'k1',
  's1',
  's2',
  'dkim'
] as const;

const DEFAULT_TIMEOUT_MS = 5_000;

const nodeResolve = dns.resolve as unknown as (hostname: string, rrtype: string) => Promise<unknown[]>;

const nodeDnsClient: DnsClient = {
  resolveTxt: dns.resolveTxt,
  resolveMx: dns.resolveMx,
  resolve: nodeResolve
};

const defaultHttpClient: HttpClient = async (input, init) => {
  if (typeof fetch !== 'function') {
    throw new Error('fetch is not available in this Node.js runtime');
  }

  return fetch(input, init);
};

interface TxtLookup {
  host: string;
  records: string[];
  error?: string;
}

interface GenericLookup<T> {
  records: T[];
  error?: string;
}

export function normalizeDomain(input: string): string {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error('Domain is required');
  }

  let hostname = trimmed;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(hostname)) {
    hostname = new URL(hostname).hostname;
  } else {
    const slashIndex = hostname.indexOf('/');
    if (slashIndex >= 0) {
      hostname = hostname.slice(0, slashIndex);
    }
  }

  hostname = hostname.toLowerCase().replace(/\.$/, '');
  const ascii = domainToASCII(hostname);
  if (ascii.length === 0) {
    throw new Error(`Invalid domain: ${input}`);
  }

  if (ascii.length > 253 || ascii.includes('..')) {
    throw new Error(`Invalid domain: ${input}`);
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ascii)) {
    throw new Error('Expected a domain name, not an IPv4 address');
  }

  const labels = ascii.split('.');
  if (labels.length < 2) {
    throw new Error('Expected a public DNS name with at least two labels');
  }

  for (const label of labels) {
    if (
      label.length === 0 ||
      label.length > 63 ||
      label.startsWith('-') ||
      label.endsWith('-') ||
      !/^[a-z0-9-]+$/.test(label)
    ) {
      throw new Error(`Invalid domain label: ${label}`);
    }
  }

  return ascii;
}

export function equivalentDomain(left: string, right: string): 'exact' | 'www-equivalent' | 'mismatch' {
  const normalizedLeft = normalizeDomain(left);
  const normalizedRight = normalizeDomain(right);

  if (normalizedLeft === normalizedRight) {
    return 'exact';
  }

  const stripWww = (value: string): string => value.replace(/^www\./, '');
  if (stripWww(normalizedLeft) === stripWww(normalizedRight)) {
    return 'www-equivalent';
  }

  return 'mismatch';
}

export async function assessDomain(input: string, options: AssessmentOptions = {}): Promise<DomainSignals> {
  const domain = normalizeDomain(input);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const dnsClient = options.dnsClient ?? nodeDnsClient;
  const httpClient = options.httpClient ?? defaultHttpClient;
  const dkimSelectors = normalizeSelectors(options.dkimSelectors ?? [...DEFAULT_DKIM_SELECTORS]);

  const dkimLookupPromise = Promise.all(
    dkimSelectors.map(async (selector) => ({
      selector,
      lookup: await lookupTxt(`${selector}._domainkey.${domain}`, dnsClient, timeoutMs)
    }))
  );

  const [
    domainTxt,
    dmarcTxt,
    domainKeyPolicy,
    mtaStsTxt,
    mxLookup,
    dsLookup,
    dnskeyLookup,
    httpsSignal,
    dkimLookups
  ] = await Promise.all([
    lookupTxt(domain, dnsClient, timeoutMs),
    lookupTxt(`_dmarc.${domain}`, dnsClient, timeoutMs),
    lookupTxt(`_domainkey.${domain}`, dnsClient, timeoutMs),
    lookupTxt(`_mta-sts.${domain}`, dnsClient, timeoutMs),
    lookupMx(domain, dnsClient, timeoutMs),
    lookupGeneric(domain, 'DS', dnsClient, timeoutMs),
    lookupGeneric(domain, 'DNSKEY', dnsClient, timeoutMs),
    checkHttps(domain, httpClient, timeoutMs),
    dkimLookupPromise
  ]);

  const mtaSts = await buildMtaStsSignal(domain, mtaStsTxt, httpClient, timeoutMs);

  return {
    domain,
    generatedAt: new Date().toISOString(),
    spf: buildSpfSignal(domainTxt),
    dkim: buildDkimSignal(dkimSelectors, domainKeyPolicy, dkimLookups),
    dmarc: buildDmarcSignal(dmarcTxt),
    mtaSts,
    mx: buildMxSignal(mxLookup),
    dnssec: buildDnssecSignal(dsLookup, dnskeyLookup),
    https: httpsSignal
  };
}

function normalizeSelectors(selectors: string[]): string[] {
  const unique = new Set<string>();
  for (const selector of selectors) {
    const normalized = selector.trim().toLowerCase();
    if (/^[a-z0-9._-]+$/.test(normalized) && normalized.length > 0) {
      unique.add(normalized);
    }
  }

  return [...unique];
}

async function lookupTxt(host: string, dnsClient: DnsClient, timeoutMs: number): Promise<TxtLookup> {
  try {
    const records = await withTimeout(dnsClient.resolveTxt(host), timeoutMs, `TXT ${host}`);
    return {
      host,
      records: records.map((chunks) => chunks.join(''))
    };
  } catch (error) {
    return {
      host,
      records: [],
      error: errorCode(error)
    };
  }
}

async function lookupMx(host: string, dnsClient: DnsClient, timeoutMs: number): Promise<GenericLookup<MxRecord>> {
  try {
    const records = await withTimeout(dnsClient.resolveMx(host), timeoutMs, `MX ${host}`);
    return { records };
  } catch (error) {
    return {
      records: [],
      error: errorCode(error)
    };
  }
}

async function lookupGeneric(
  host: string,
  rrtype: string,
  dnsClient: DnsClient,
  timeoutMs: number
): Promise<GenericLookup<unknown>> {
  try {
    const records = await withTimeout(dnsClient.resolve(host, rrtype), timeoutMs, `${rrtype} ${host}`);
    return { records };
  } catch (error) {
    return {
      records: [],
      error: errorCode(error)
    };
  }
}

function buildSpfSignal(lookup: TxtLookup): SpfSignal {
  const records = lookup.records.filter((record) => record.trim().toLowerCase().startsWith('v=spf1'));
  const warnings: string[] = [];
  const signal: SpfSignal = {
    present: records.length > 0,
    records,
    warnings
  };

  if (lookup.error !== undefined) {
    signal.error = lookup.error;
  }

  if (records.length > 1) {
    warnings.push('Multiple SPF records were found; receivers may treat this as a permanent error.');
  }

  const selectedRecord = records[0];
  if (selectedRecord !== undefined) {
    signal.selectedRecord = selectedRecord;
    const allMatch = selectedRecord.match(/(?:^|\s)([+~?-]?)(all)(?=\s|$)/i);
    if (allMatch !== null) {
      const qualifier = normalizeSpfQualifier(allMatch[1] ?? '+');
      signal.allQualifier = qualifier;
      signal.allMechanism = `${qualifier === '+' ? '' : qualifier}all`;
      if (qualifier === '+' || qualifier === '?') {
        warnings.push('SPF all mechanism is permissive.');
      }
    } else {
      warnings.push('SPF record has no all mechanism.');
    }
  }

  return signal;
}

function normalizeSpfQualifier(value: string): '+' | '-' | '~' | '?' {
  if (value === '-' || value === '~' || value === '?') {
    return value;
  }

  return '+';
}

function buildDkimSignal(
  selectorsChecked: string[],
  domainKeyPolicy: TxtLookup,
  selectorLookups: Array<{ selector: string; lookup: TxtLookup }>
): DkimSignal {
  const selectorsFound: string[] = [];
  const errors: Record<string, string> = {};

  for (const item of selectorLookups) {
    if (item.lookup.records.some((record) => record.toLowerCase().includes('v=dkim1'))) {
      selectorsFound.push(item.selector);
    }

    if (item.lookup.error !== undefined) {
      errors[item.selector] = item.lookup.error;
    }
  }

  const policyRecords = domainKeyPolicy.records.filter((record) => {
    const lower = record.toLowerCase();
    return lower.includes('v=dkim1') || lower.includes('o=');
  });

  if (domainKeyPolicy.error !== undefined) {
    errors._domainkey = domainKeyPolicy.error;
  }

  return {
    present: selectorsFound.length > 0,
    selectorsChecked,
    selectorsFound,
    domainKeyPolicyPresent: policyRecords.length > 0,
    policyRecords,
    errors
  };
}

function buildDmarcSignal(lookup: TxtLookup): DmarcSignal {
  const records = lookup.records.filter((record) => record.trim().toLowerCase().startsWith('v=dmarc1'));
  const selectedRecord = records[0];
  const tags = selectedRecord === undefined ? {} : parseTagRecord(selectedRecord);
  const policy = parseDmarcPolicy(tags.p);
  const subdomainPolicy = tags.sp === undefined ? undefined : parseDmarcPolicy(tags.sp);
  const pct = parsePct(tags.pct);

  const signal: DmarcSignal = {
    present: records.length > 0,
    records,
    policy,
    ruaPresent: tags.rua !== undefined && tags.rua.trim().length > 0,
    tags
  };

  if (selectedRecord !== undefined) {
    signal.selectedRecord = selectedRecord;
  }
  if (subdomainPolicy !== undefined) {
    signal.subdomainPolicy = subdomainPolicy;
  }
  if (pct !== undefined) {
    signal.pct = pct;
  }
  if (lookup.error !== undefined) {
    signal.error = lookup.error;
  }

  return signal;
}

async function buildMtaStsSignal(
  domain: string,
  txtLookup: TxtLookup,
  httpClient: HttpClient,
  timeoutMs: number
): Promise<MtaStsSignal> {
  const txtRecords = txtLookup.records.filter((record) => record.trim().toLowerCase().startsWith('v=stsv1'));
  const signal: MtaStsSignal = {
    dnsPresent: txtRecords.length > 0,
    txtRecords,
    policyReachable: false,
    policyMode: 'unknown'
  };

  if (txtLookup.error !== undefined) {
    signal.error = txtLookup.error;
  }

  if (txtRecords.length === 0) {
    return signal;
  }

  try {
    const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
    const response = await fetchWithTimeout(policyUrl, httpClient, timeoutMs, 'GET');
    if (!response.ok) {
      signal.error = `HTTP_${response.status}`;
      return signal;
    }

    const text = await response.text();
    signal.policyText = text;
    signal.policyMode = parseMtaStsMode(text);
    signal.policyReachable = text.toLowerCase().includes('version: stsv1');
    return signal;
  } catch (error) {
    signal.error = errorCode(error);
    return signal;
  }
}

function buildMxSignal(lookup: GenericLookup<MxRecord>): MxSignal {
  const records = [...lookup.records].sort((left, right) => left.priority - right.priority);
  const signal: MxSignal = {
    present: records.length > 0,
    records
  };

  if (lookup.error !== undefined) {
    signal.error = lookup.error;
  }

  return signal;
}

function buildDnssecSignal(dsLookup: GenericLookup<unknown>, dnskeyLookup: GenericLookup<unknown>): DnssecSignal {
  const dsPresent = dsLookup.records.length > 0;
  const dnskeyPresent = dnskeyLookup.records.length > 0;
  const status = dsPresent ? 'signed' : dnskeyPresent ? 'dnskey-only' : 'unsigned';
  const signal: DnssecSignal = {
    dsPresent,
    dnskeyPresent,
    status
  };

  if (dsLookup.error !== undefined) {
    signal.dsError = dsLookup.error;
  }
  if (dnskeyLookup.error !== undefined) {
    signal.dnskeyError = dnskeyLookup.error;
  }
  if (dsLookup.error !== undefined && dnskeyLookup.error !== undefined) {
    signal.status = 'unknown';
  }

  return signal;
}

async function checkHttps(domain: string, httpClient: HttpClient, timeoutMs: number): Promise<HttpsSignal> {
  try {
    const response = await fetchWithTimeout(`https://${domain}/`, httpClient, timeoutMs, 'HEAD');
    const signal: HttpsSignal = {
      attempted: true,
      reachable: true,
      tlsOk: true,
      statusCode: response.status,
      hsts: response.headers.get('strict-transport-security') !== null
    };

    return signal;
  } catch (error) {
    return {
      attempted: true,
      reachable: false,
      tlsOk: false,
      hsts: false,
      error: errorCode(error)
    };
  }
}

async function fetchWithTimeout(
  url: string,
  httpClient: HttpClient,
  timeoutMs: number,
  method: 'GET' | 'HEAD'
) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await httpClient(url, {
      method,
      redirect: 'manual',
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

function parseTagRecord(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const rawPart of record.split(';')) {
    const part = rawPart.trim();
    if (part.length === 0) {
      continue;
    }

    const separatorIndex = part.indexOf('=');
    if (separatorIndex <= 0) {
      continue;
    }

    const key = part.slice(0, separatorIndex).trim().toLowerCase();
    const value = part.slice(separatorIndex + 1).trim();
    if (key.length > 0) {
      tags[key] = value;
    }
  }

  return tags;
}

function parseDmarcPolicy(value: string | undefined): DmarcPolicy {
  if (value === undefined) {
    return 'missing';
  }

  switch (value.toLowerCase()) {
    case 'none':
      return 'none';
    case 'quarantine':
      return 'quarantine';
    case 'reject':
      return 'reject';
    default:
      return 'unknown';
  }
}

function parsePct(value: string | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return undefined;
  }

  return parsed;
}

function parseMtaStsMode(text: string): MtaStsMode {
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim().toLowerCase();
    if (!line.startsWith('mode:')) {
      continue;
    }

    const mode = line.slice('mode:'.length).trim();
    if (mode === 'enforce' || mode === 'testing' || mode === 'none') {
      return mode;
    }

    return 'unknown';
  }

  return 'unknown';
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => reject(new Error(`TIMEOUT_${label}`)), timeoutMs);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

function errorCode(error: unknown): string {
  if (error instanceof Error) {
    const maybeWithCode = error as Error & { code?: unknown };
    if (typeof maybeWithCode.code === 'string') {
      return maybeWithCode.code;
    }

    return error.message.length > 0 ? error.message : error.name;
  }

  return 'UNKNOWN';
}
