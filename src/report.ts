import { resolveOivContext } from './oiv.js';
import { assessDomain, normalizeDomain } from './posture.js';
import { buildRemediations, scoreSignals } from './scoring.js';
import type { AssessmentOptions, EthicsStatement, RiskCheckReport } from './types.js';
import { VERSION } from './version.js';

export interface BuildReportInput extends AssessmentOptions {
  domain?: string;
  rut?: string;
  name?: string;
  selfAttested: boolean;
}

export async function buildRiskCheckReport(input: BuildReportInput): Promise<RiskCheckReport> {
  const generatedAt = new Date().toISOString();
  const requestedDomain = input.domain === undefined ? undefined : normalizeDomain(input.domain);
  const initialOiv = await resolveOivContext(buildOivLookup(input.rut, input.name, requestedDomain));

  let assessmentDomain = requestedDomain;
  if (assessmentDomain === undefined && input.selfAttested && initialOiv.canonicalDomain !== undefined) {
    assessmentDomain = normalizeDomain(initialOiv.canonicalDomain);
  }

  if (assessmentDomain !== undefined && !input.selfAttested) {
    throw new Error('Domain assessment requires --self-attest / --i-own-this-domain.');
  }

  const oiv =
    assessmentDomain === requestedDomain
      ? initialOiv
      : await resolveOivContext(buildOivLookup(input.rut, input.name, assessmentDomain));

  const report: RiskCheckReport = {
    tool: {
      name: 'reizan-oiv-risk-check',
      version: VERSION
    },
    generatedAt,
    target: buildTarget(assessmentDomain, input.rut, input.name),
    ethics: buildEthics(input.selfAttested),
    oiv
  };

  if (assessmentDomain !== undefined) {
    const signals = await assessDomain(assessmentDomain, buildAssessmentOptions(input));
    const score = scoreSignals(signals);
    report.assessment = {
      signals,
      score,
      remediations: buildRemediations(signals, oiv)
    };
  }

  return report;
}

function buildOivLookup(
  rut: string | undefined,
  name: string | undefined,
  domain: string | undefined
): Parameters<typeof resolveOivContext>[0] {
  const lookup: Parameters<typeof resolveOivContext>[0] = {};
  if (rut !== undefined) {
    lookup.rut = rut;
  }
  if (name !== undefined) {
    lookup.name = name;
  }
  if (domain !== undefined) {
    lookup.domain = domain;
  }

  return lookup;
}

function buildAssessmentOptions(input: BuildReportInput): AssessmentOptions {
  const options: AssessmentOptions = {};
  if (input.dkimSelectors !== undefined) {
    options.dkimSelectors = input.dkimSelectors;
  }
  if (input.timeoutMs !== undefined) {
    options.timeoutMs = input.timeoutMs;
  }
  if (input.dnsClient !== undefined) {
    options.dnsClient = input.dnsClient;
  }
  if (input.httpClient !== undefined) {
    options.httpClient = input.httpClient;
  }

  return options;
}

export function renderTextReport(report: RiskCheckReport): string {
  const lines: string[] = [];

  lines.push('reizan-oiv-risk-check');
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push('Ethics: self-assessment only; passive DNS; no port scanning; minimal HTTPS reachability.');
  lines.push('');

  lines.push('Target');
  lines.push(`  Domain: ${report.target.domain ?? 'not assessed'}`);
  lines.push(`  RUT: ${report.target.rut ?? 'not provided'}`);
  if (report.target.name !== undefined) {
    lines.push(`  Name: ${report.target.name}`);
  }
  lines.push('');

  lines.push('OIV designation');
  lines.push(`  Designated OIV: ${report.oiv.designated ? 'yes' : 'no'}`);
  lines.push(`  Sector: ${report.oiv.sector ?? 'not found'}`);
  lines.push(`  FASE: ${report.oiv.fase ?? 'not published by resolver'}`);
  lines.push(`  FASE source: ${report.oiv.faseSource}`);
  if (report.oiv.canonicalDomain !== undefined) {
    lines.push(`  Resolver domain: ${report.oiv.canonicalDomain}`);
  }
  if (report.oiv.domainStatus !== undefined) {
    lines.push(`  Resolver domain status: ${report.oiv.domainStatus}`);
  }
  if (report.oiv.domainRelation !== undefined) {
    lines.push(`  Domain relation: ${report.oiv.domainRelation}`);
  }
  if (report.oiv.warning !== undefined) {
    lines.push(`  Warning: ${report.oiv.warning}`);
  }
  lines.push('');

  if (report.assessment === undefined) {
    lines.push('Assessment skipped');
    lines.push('  Provide --domain with --self-attest, or provide --rut with --self-attest to assess the resolver canonical domain.');
    return lines.join('\n');
  }

  lines.push(`Maturity score: ${report.assessment.score.total}/${report.assessment.score.max} (${report.assessment.score.band})`);
  lines.push(`Model: ${report.assessment.score.modelVersion}`);
  lines.push('');
  lines.push('Controls');
  for (const item of report.assessment.score.items) {
    lines.push(`  ${statusMarker(item.status)} ${item.label.padEnd(10)} ${String(item.points).padStart(2)}/${item.maxPoints}  ${item.evidence}`);
  }
  lines.push('');

  lines.push('Observed posture');
  lines.push(`  SPF: ${report.assessment.signals.spf.selectedRecord ?? 'not found'}`);
  lines.push(`  DMARC: ${report.assessment.signals.dmarc.selectedRecord ?? 'not found'}`);
  lines.push(`  DKIM selectors found: ${report.assessment.signals.dkim.selectorsFound.join(', ') || 'none in checked selector set'}`);
  lines.push(`  MX: ${report.assessment.signals.mx.records.map((record) => `${record.priority} ${record.exchange}`).join('; ') || 'not found'}`);
  lines.push(`  MTA-STS: ${report.assessment.signals.mtaSts.dnsPresent ? `present, mode=${report.assessment.signals.mtaSts.policyMode}` : 'not found'}`);
  lines.push(`  DNSSEC: ${report.assessment.signals.dnssec.status}`);
  lines.push(`  HTTPS: ${report.assessment.signals.https.reachable ? `reachable, status=${report.assessment.signals.https.statusCode ?? 'unknown'}, hsts=${String(report.assessment.signals.https.hsts)}` : `failed (${report.assessment.signals.https.error ?? 'unknown'})`}`);
  lines.push('');

  lines.push('Remediation');
  report.assessment.remediations.forEach((remediation, index) => {
    lines.push(`  ${index + 1}. [${remediation.priority}] ${remediation.control}: ${remediation.action}`);
    lines.push(`     Ley 21.663 tie: ${remediation.ley21663Tie}`);
  });
  lines.push('');
  lines.push('Note: informational self-assessment only; not legal advice.');

  return lines.join('\n');
}

function buildTarget(domain: string | undefined, rut: string | undefined, name: string | undefined): RiskCheckReport['target'] {
  const target: RiskCheckReport['target'] = {};
  if (domain !== undefined) {
    target.domain = domain;
  }
  if (rut !== undefined) {
    target.rut = rut;
  }
  if (name !== undefined) {
    target.name = name;
  }

  return target;
}

function buildEthics(selfAttested: boolean): EthicsStatement {
  return {
    selfAssessmentOnly: true,
    selfAttested,
    passiveDnsOnly: true,
    noPortScanning: true,
    minimalHttpsFetch: true,
    note: 'Use only for domains controlled by the running entity. The CLI performs DNS lookups and minimal HTTPS fetches; it never performs port scanning.'
  };
}

function statusMarker(status: string): string {
  switch (status) {
    case 'pass':
      return '[ok]  ';
    case 'warn':
      return '[warn]';
    case 'fail':
      return '[fail]';
    default:
      return '[?]   ';
  }
}
