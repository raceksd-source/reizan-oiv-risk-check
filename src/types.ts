export type DmarcPolicy = 'none' | 'quarantine' | 'reject' | 'missing' | 'unknown';

export type MtaStsMode = 'enforce' | 'testing' | 'none' | 'unknown';

export type DnssecStatus = 'signed' | 'dnskey-only' | 'unsigned' | 'unknown';

export type ScoreBand = 'Initial' | 'Basic' | 'Managed' | 'Mature';

export type FindingStatus = 'pass' | 'warn' | 'fail' | 'unknown';

export type RemediationPriority = 'high' | 'medium' | 'low';

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface SpfSignal {
  present: boolean;
  records: string[];
  selectedRecord?: string;
  allMechanism?: string;
  allQualifier?: '+' | '-' | '~' | '?';
  warnings: string[];
  error?: string;
}

export interface DkimSignal {
  present: boolean;
  selectorsChecked: string[];
  selectorsFound: string[];
  domainKeyPolicyPresent: boolean;
  policyRecords: string[];
  errors: Record<string, string>;
}

export interface DmarcSignal {
  present: boolean;
  records: string[];
  selectedRecord?: string;
  policy: DmarcPolicy;
  subdomainPolicy?: DmarcPolicy;
  ruaPresent: boolean;
  pct?: number;
  tags: Record<string, string>;
  error?: string;
}

export interface MtaStsSignal {
  dnsPresent: boolean;
  txtRecords: string[];
  policyReachable: boolean;
  policyMode: MtaStsMode;
  policyText?: string;
  error?: string;
}

export interface MxSignal {
  present: boolean;
  records: MxRecord[];
  error?: string;
}

export interface DnssecSignal {
  dsPresent: boolean;
  dnskeyPresent: boolean;
  status: DnssecStatus;
  dsError?: string;
  dnskeyError?: string;
}

export interface HttpsSignal {
  attempted: boolean;
  reachable: boolean;
  tlsOk: boolean;
  statusCode?: number;
  hsts: boolean;
  error?: string;
}

export interface DomainSignals {
  domain: string;
  generatedAt: string;
  spf: SpfSignal;
  dkim: DkimSignal;
  dmarc: DmarcSignal;
  mtaSts: MtaStsSignal;
  mx: MxSignal;
  dnssec: DnssecSignal;
  https: HttpsSignal;
}

export interface ScoreItem {
  id: string;
  label: string;
  status: FindingStatus;
  points: number;
  maxPoints: number;
  evidence: string;
}

export interface ScoreResult {
  total: number;
  max: 100;
  band: ScoreBand;
  modelVersion: '2026-06';
  items: ScoreItem[];
}

export interface Remediation {
  priority: RemediationPriority;
  control: string;
  finding: string;
  action: string;
  ley21663Tie: string;
}

export interface OivContext {
  designated: boolean;
  lookup: 'rut' | 'domain' | 'rut-and-domain' | 'none';
  rut?: string;
  razonSocial?: string;
  canonicalDomain?: string;
  sector?: string;
  fase: string | null;
  faseSource: string;
  resolverSource?: string;
  confidence?: number;
  domainStatus?: string;
  domainRelation?: 'exact' | 'www-equivalent' | 'mismatch' | 'not-checked';
  warning?: string;
}

export interface EthicsStatement {
  selfAssessmentOnly: true;
  selfAttested: boolean;
  passiveDnsOnly: true;
  noPortScanning: true;
  minimalHttpsFetch: true;
  note: string;
}

export interface RiskCheckReport {
  tool: {
    name: 'reizan-oiv-risk-check';
    version: string;
  };
  generatedAt: string;
  target: {
    domain?: string;
    rut?: string;
    name?: string;
  };
  ethics: EthicsStatement;
  oiv: OivContext;
  assessment?: {
    signals: DomainSignals;
    score: ScoreResult;
    remediations: Remediation[];
  };
}

export interface DnsClient {
  resolveTxt(hostname: string): Promise<string[][]>;
  resolveMx(hostname: string): Promise<MxRecord[]>;
  resolve(hostname: string, rrtype: string): Promise<unknown[]>;
}

export interface HttpResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
  headers: {
    get(name: string): string | null;
  };
}

export type HttpClient = (input: string, init: RequestInit) => Promise<HttpResponse>;

export interface AssessmentOptions {
  dkimSelectors?: string[];
  timeoutMs?: number;
  dnsClient?: DnsClient;
  httpClient?: HttpClient;
}
