import {
  getAllEntries,
  normalizeRut,
  resolveBytable,
  resolveOIVDomain,
  type OIVDomainResolution
} from 'anci-oiv-resolver';

import { equivalentDomain, normalizeDomain } from './posture.js';
import type { OivContext } from './types.js';

interface OivLookupInput {
  rut?: string;
  name?: string;
  domain?: string;
}

interface ResolverEntry {
  rut: string;
  domain: string;
  razon_social: string;
  sector: string;
  dns_verified: boolean;
  domain_status?: string;
}

const FASE_SOURCE = 'anci-oiv-resolver@0.6.0 does not publish a FASE field; value is not inferred.';

export async function resolveOivContext(input: OivLookupInput): Promise<OivContext> {
  const normalizedDomain = input.domain === undefined ? undefined : normalizeDomain(input.domain);

  if (input.rut !== undefined) {
    return resolveByRut(input.rut, input.name, normalizedDomain);
  }

  if (normalizedDomain !== undefined) {
    return resolveByDomain(normalizedDomain);
  }

  return {
    designated: false,
    lookup: 'none',
    fase: null,
    faseSource: FASE_SOURCE,
    warning: 'No RUT or domain was provided for OIV designation lookup.'
  };
}

function contextFromResolution(
  resolution: Omit<OIVDomainResolution, 'verified' | 'mxRecords'>,
  lookup: OivContext['lookup'],
  assessedDomain?: string
): OivContext {
  const relation = assessedDomain === undefined ? 'not-checked' : equivalentDomain(resolution.domain, assessedDomain);
  const context: OivContext = {
    designated: true,
    lookup,
    rut: resolution.rut,
    razonSocial: resolution.razonSocial,
    canonicalDomain: resolution.domain,
    sector: resolution.sector,
    fase: null,
    faseSource: FASE_SOURCE,
    resolverSource: resolution.source,
    confidence: resolution.confidence,
    domainRelation: relation
  };

  if (resolution.domain_status !== undefined) {
    context.domainStatus = resolution.domain_status;
  }

  if (relation === 'mismatch') {
    context.warning = `Assessed domain ${assessedDomain ?? ''} does not match resolver canonical domain ${resolution.domain}.`;
  }

  return context;
}

async function resolveByRut(rut: string, name: string | undefined, assessedDomain: string | undefined): Promise<OivContext> {
  const tableResolution = resolveBytable(rut);
  if (tableResolution !== null) {
    return contextFromResolution(tableResolution, assessedDomain === undefined ? 'rut' : 'rut-and-domain', assessedDomain);
  }

  if (name !== undefined && name.trim().length > 0) {
    const heuristicResolution = await resolveOIVDomain(rut, name, { verify: false });
    const context = contextFromResolution(heuristicResolution, assessedDomain === undefined ? 'rut' : 'rut-and-domain', assessedDomain);
    context.designated = heuristicResolution.source === 'known-domains';
    if (!context.designated) {
      context.warning = 'RUT was not found in the OIV table; resolver returned a heuristic domain candidate only.';
    }
    return context;
  }

  const context: OivContext = {
    designated: false,
    lookup: assessedDomain === undefined ? 'rut' : 'rut-and-domain',
    rut: normalizeRut(rut),
    fase: null,
    faseSource: FASE_SOURCE,
    warning: 'RUT was not found in the published OIV resolver table.'
  };

  if (assessedDomain !== undefined) {
    context.domainRelation = 'not-checked';
  }

  return context;
}

function resolveByDomain(domain: string): OivContext {
  const entries = getAllEntries() as ResolverEntry[];
  const match = entries.find((entry) => equivalentDomain(entry.domain, domain) !== 'mismatch');

  if (match === undefined) {
    return {
      designated: false,
      lookup: 'domain',
      canonicalDomain: domain,
      fase: null,
      faseSource: FASE_SOURCE,
      domainRelation: 'not-checked',
      warning: 'Domain was not found as a canonical OIV domain in the resolver table.'
    };
  }

  const relation = equivalentDomain(match.domain, domain);
  const context: OivContext = {
    designated: true,
    lookup: 'domain',
    rut: normalizeRut(match.rut),
    razonSocial: match.razon_social,
    canonicalDomain: match.domain,
    sector: match.sector,
    fase: null,
    faseSource: FASE_SOURCE,
    resolverSource: 'known-domains',
    confidence: match.dns_verified ? 1 : 0.85,
    domainRelation: relation
  };

  if (match.domain_status !== undefined) {
    context.domainStatus = match.domain_status;
  }

  return context;
}
