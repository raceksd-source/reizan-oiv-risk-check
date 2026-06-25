export { buildRiskCheckReport, renderTextReport, type BuildReportInput } from './report.js';
export { resolveOivContext } from './oiv.js';
export { assessDomain, DEFAULT_DKIM_SELECTORS, equivalentDomain, normalizeDomain } from './posture.js';
export { buildRemediations, scoreBand, scoreSignals } from './scoring.js';
export type {
  AssessmentOptions,
  DkimSignal,
  DmarcSignal,
  DnsClient,
  DnssecSignal,
  DomainSignals,
  EthicsStatement,
  HttpClient,
  HttpResponse,
  HttpsSignal,
  MtaStsSignal,
  MxRecord,
  MxSignal,
  OivContext,
  Remediation,
  RiskCheckReport,
  ScoreItem,
  ScoreResult,
  SpfSignal
} from './types.js';
