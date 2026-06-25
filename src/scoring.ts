import type {
  DomainSignals,
  FindingStatus,
  OivContext,
  Remediation,
  RemediationPriority,
  ScoreBand,
  ScoreItem,
  ScoreResult
} from './types.js';

const LEY_TIE =
  'Supports Ley 21.663 deber-de-seguridad by reducing foreseeable abuse, strengthening continuity, and creating auditable baseline controls.';

export function scoreSignals(signals: DomainSignals): ScoreResult {
  const items: ScoreItem[] = [
    scoreSpf(signals),
    scoreDmarc(signals),
    scoreDkim(signals),
    scoreMx(signals),
    scoreMtaSts(signals),
    scoreHttps(signals),
    scoreDnssec(signals)
  ];

  const total = items.reduce((sum, item) => sum + item.points, 0);

  return {
    total,
    max: 100,
    band: scoreBand(total),
    modelVersion: '2026-06',
    items
  };
}

export function buildRemediations(signals: DomainSignals, oiv: OivContext): Remediation[] {
  const remediations: Remediation[] = [];
  const oivPrefix = oiv.designated ? 'As a designated OIV, prioritize this as compliance evidence. ' : '';

  if (!signals.spf.present) {
    remediations.push(remediation('high', 'SPF', 'No SPF record was found.', `${oivPrefix}Publish a single SPF record at the apex domain with only authorized senders and an eventual -all policy.`));
  } else if (signals.spf.allQualifier !== '-') {
    remediations.push(remediation('medium', 'SPF', `SPF is present but ends with ${signals.spf.allMechanism ?? 'no all mechanism'}.`, `${oivPrefix}Move SPF toward a hard-fail -all policy after confirming all legitimate mail sources.`));
  }

  if (!signals.dkim.present) {
    remediations.push(remediation('high', 'DKIM', 'No DKIM selector was found in the checked passive selector set.', `${oivPrefix}Enable DKIM signing on all outbound mail platforms and publish stable selectors; keep selector inventory as audit evidence.`));
  }

  if (!signals.dmarc.present) {
    remediations.push(remediation('high', 'DMARC', 'No DMARC policy was found.', `${oivPrefix}Publish DMARC with aggregate reporting, then progress from p=none to p=quarantine and p=reject using measured rollout.`));
  } else if (signals.dmarc.policy === 'none') {
    remediations.push(remediation('medium', 'DMARC', 'DMARC is monitoring-only with p=none.', `${oivPrefix}Use reports to close SPF/DKIM alignment gaps, then move to p=quarantine or p=reject.`));
  } else if (signals.dmarc.policy === 'quarantine') {
    remediations.push(remediation('low', 'DMARC', 'DMARC is enforcing quarantine but not reject.', `${oivPrefix}Plan a controlled migration to p=reject once false positives are addressed.`));
  }

  if (!signals.mx.present) {
    remediations.push(remediation('high', 'MX', 'No MX records were found.', `${oivPrefix}Publish monitored MX records for the assessed domain or document why the domain intentionally does not receive email.`));
  } else if (distinctMxExchanges(signals) < 2) {
    remediations.push(remediation('medium', 'MX', 'Only one MX exchange was found.', `${oivPrefix}Add redundant MX service paths or document compensating resilience controls.`));
  }

  if (!signals.mtaSts.dnsPresent) {
    remediations.push(remediation('medium', 'MTA-STS', 'No MTA-STS TXT record was found.', `${oivPrefix}Publish _mta-sts TXT and host a valid policy at https://mta-sts.<domain>/.well-known/mta-sts.txt; add TLS-RPT for monitoring.`));
  } else if (!signals.mtaSts.policyReachable || signals.mtaSts.policyMode !== 'enforce') {
    remediations.push(remediation('medium', 'MTA-STS', 'MTA-STS is present but the policy is not reachable in enforce mode.', `${oivPrefix}Repair the HTTPS policy host and move mode from testing/none to enforce after validation.`));
  }

  if (!signals.https.reachable) {
    remediations.push(remediation('medium', 'HTTPS', 'HTTPS reachability failed for the apex domain.', `${oivPrefix}Ensure the public web endpoint presents a valid TLS certificate and responds predictably on HTTPS.`));
  } else if (!signals.https.hsts) {
    remediations.push(remediation('low', 'HTTPS', 'HTTPS is reachable but HSTS was not observed.', `${oivPrefix}Deploy Strict-Transport-Security after confirming all required subdomains support HTTPS.`));
  }

  if (signals.dnssec.status !== 'signed') {
    remediations.push(remediation('medium', 'DNSSEC', 'No DS-backed DNSSEC chain was observed.', `${oivPrefix}Enable DNSSEC at the authoritative DNS provider and publish DS records through the registrar/NIC.`));
  }

  if (remediations.length === 0) {
    remediations.push(remediation('low', 'Evidence', 'No high-priority gaps were detected by this passive check.', `${oivPrefix}Preserve DNS exports, policy screenshots, and change records as security-duty evidence for periodic review.`));
  }

  return remediations;
}

export function scoreBand(score: number): ScoreBand {
  if (score >= 80) {
    return 'Mature';
  }
  if (score >= 60) {
    return 'Managed';
  }
  if (score >= 40) {
    return 'Basic';
  }

  return 'Initial';
}

function scoreSpf(signals: DomainSignals): ScoreItem {
  if (!signals.spf.present) {
    return item('spf', 'SPF', 'fail', 0, 15, 'No SPF record found.');
  }

  if (signals.spf.allQualifier === '-') {
    return item('spf', 'SPF', 'pass', 15, 15, `SPF present with ${signals.spf.allMechanism}.`);
  }

  if (signals.spf.allQualifier === '~') {
    return item('spf', 'SPF', 'warn', 12, 15, 'SPF present with soft-fail ~all.');
  }

  if (signals.spf.allQualifier === '?' || signals.spf.allQualifier === '+') {
    return item('spf', 'SPF', 'warn', 8, 15, `SPF present with permissive ${signals.spf.allMechanism}.`);
  }

  return item('spf', 'SPF', 'warn', 10, 15, 'SPF present but no all mechanism was found.');
}

function scoreDmarc(signals: DomainSignals): ScoreItem {
  switch (signals.dmarc.policy) {
    case 'reject':
      return item('dmarc', 'DMARC', 'pass', 20, 20, 'DMARC p=reject.');
    case 'quarantine':
      return item('dmarc', 'DMARC', 'warn', 16, 20, 'DMARC p=quarantine.');
    case 'none':
      return item('dmarc', 'DMARC', 'warn', 8, 20, 'DMARC p=none.');
    case 'missing':
      return item('dmarc', 'DMARC', 'fail', 0, 20, 'No DMARC record found.');
    case 'unknown':
      return item('dmarc', 'DMARC', 'unknown', 4, 20, 'DMARC record has an unknown policy.');
  }
}

function scoreDkim(signals: DomainSignals): ScoreItem {
  if (signals.dkim.present) {
    return item('dkim', 'DKIM', 'pass', 10, 10, `DKIM selector(s) found: ${signals.dkim.selectorsFound.join(', ')}.`);
  }

  if (signals.dkim.domainKeyPolicyPresent) {
    return item('dkim', 'DKIM', 'unknown', 4, 10, 'DomainKey policy record found, but no DKIM selector matched the passive selector set.');
  }

  return item('dkim', 'DKIM', 'fail', 0, 10, 'No DKIM selector found in the passive selector set.');
}

function scoreMx(signals: DomainSignals): ScoreItem {
  const distinct = distinctMxExchanges(signals);
  if (distinct >= 2) {
    return item('mx', 'MX', 'pass', 10, 10, `${distinct} distinct MX exchanges found.`);
  }

  if (distinct === 1) {
    return item('mx', 'MX', 'warn', 6, 10, 'One MX exchange found.');
  }

  return item('mx', 'MX', 'fail', 0, 10, 'No MX records found.');
}

function scoreMtaSts(signals: DomainSignals): ScoreItem {
  if (signals.mtaSts.dnsPresent && signals.mtaSts.policyReachable && signals.mtaSts.policyMode === 'enforce') {
    return item('mta-sts', 'MTA-STS', 'pass', 10, 10, 'MTA-STS TXT and enforce policy found.');
  }

  if (signals.mtaSts.dnsPresent && signals.mtaSts.policyReachable) {
    return item('mta-sts', 'MTA-STS', 'warn', 7, 10, `MTA-STS policy reachable with mode=${signals.mtaSts.policyMode}.`);
  }

  if (signals.mtaSts.dnsPresent) {
    return item('mta-sts', 'MTA-STS', 'warn', 4, 10, 'MTA-STS TXT found, but policy was not reachable.');
  }

  return item('mta-sts', 'MTA-STS', 'fail', 0, 10, 'No MTA-STS TXT record found.');
}

function scoreHttps(signals: DomainSignals): ScoreItem {
  if (signals.https.reachable && signals.https.hsts) {
    return item('https', 'HTTPS/TLS', 'pass', 15, 15, `HTTPS reachable with HSTS; status ${signals.https.statusCode ?? 'unknown'}.`);
  }

  if (signals.https.reachable) {
    return item('https', 'HTTPS/TLS', 'warn', 10, 15, `HTTPS reachable; HSTS not observed; status ${signals.https.statusCode ?? 'unknown'}.`);
  }

  return item('https', 'HTTPS/TLS', 'fail', 0, 15, `HTTPS reachability failed${signals.https.error === undefined ? '.' : `: ${signals.https.error}.`}`);
}

function scoreDnssec(signals: DomainSignals): ScoreItem {
  if (signals.dnssec.status === 'signed') {
    return item('dnssec', 'DNSSEC', 'pass', 20, 20, 'DS record found.');
  }

  if (signals.dnssec.status === 'dnskey-only') {
    return item('dnssec', 'DNSSEC', 'warn', 12, 20, 'DNSKEY found but no DS record was observed.');
  }

  if (signals.dnssec.status === 'unknown') {
    return item('dnssec', 'DNSSEC', 'unknown', 4, 20, 'DNSSEC lookup was inconclusive.');
  }

  return item('dnssec', 'DNSSEC', 'fail', 0, 20, 'No DS/DNSKEY evidence found.');
}

function item(
  id: string,
  label: string,
  status: FindingStatus,
  points: number,
  maxPoints: number,
  evidence: string
): ScoreItem {
  return {
    id,
    label,
    status,
    points,
    maxPoints,
    evidence
  };
}

function remediation(
  priority: RemediationPriority,
  control: string,
  finding: string,
  action: string
): Remediation {
  return {
    priority,
    control,
    finding,
    action,
    ley21663Tie: LEY_TIE
  };
}

function distinctMxExchanges(signals: DomainSignals): number {
  return new Set(signals.mx.records.map((record) => record.exchange.toLowerCase().replace(/\.$/, ''))).size;
}
