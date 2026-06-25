#!/usr/bin/env node
import { pathToFileURL } from 'node:url';

import { buildRiskCheckReport, renderTextReport } from './report.js';
import type { BuildReportInput } from './report.js';
import { VERSION } from './version.js';

interface CliOptions {
  domain?: string;
  rut?: string;
  name?: string;
  json: boolean;
  selfAttested: boolean;
  dkimSelectors?: string[];
  timeoutMs?: number;
  help: boolean;
  version: boolean;
}

class CliError extends Error {
  constructor(message: string, readonly exitCode = 1) {
    super(message);
  }
}

export function parseCliArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    json: false,
    selfAttested: false,
    help: false,
    version: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const rawArg = argv[index];
    if (rawArg === undefined) {
      continue;
    }

    const { flag, inlineValue } = splitArg(rawArg);
    switch (flag) {
      case '--domain':
        options.domain = readValue(argv, index, inlineValue, flag);
        if (inlineValue === undefined) {
          index += 1;
        }
        break;
      case '--rut':
        options.rut = readValue(argv, index, inlineValue, flag);
        if (inlineValue === undefined) {
          index += 1;
        }
        break;
      case '--name':
      case '--razon-social':
        options.name = readValue(argv, index, inlineValue, flag);
        if (inlineValue === undefined) {
          index += 1;
        }
        break;
      case '--dkim-selectors': {
        const value = readValue(argv, index, inlineValue, flag);
        options.dkimSelectors = value.split(',').map((item) => item.trim()).filter(Boolean);
        if (inlineValue === undefined) {
          index += 1;
        }
        break;
      }
      case '--timeout-ms': {
        const value = Number.parseInt(readValue(argv, index, inlineValue, flag), 10);
        if (!Number.isFinite(value) || value < 500) {
          throw new CliError('--timeout-ms must be an integer >= 500');
        }
        options.timeoutMs = value;
        if (inlineValue === undefined) {
          index += 1;
        }
        break;
      }
      case '--json':
        options.json = true;
        break;
      case '--self-attest':
      case '--i-own-this-domain':
        options.selfAttested = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      case '--version':
      case '-v':
        options.version = true;
        break;
      default:
        throw new CliError(`Unknown option: ${flag}`);
    }
  }

  return options;
}

export async function runCli(argv: string[]): Promise<number> {
  const options = parseCliArgs(argv);

  if (options.help) {
    console.log(usage());
    return 0;
  }

  if (options.version) {
    console.log(VERSION);
    return 0;
  }

  if (options.domain === undefined && options.rut === undefined) {
    throw new CliError('Provide --domain, --rut, or both. Use --help for examples.');
  }

  const reportInput: BuildReportInput = {
    selfAttested: options.selfAttested
  };

  if (options.domain !== undefined) {
    reportInput.domain = options.domain;
  }
  if (options.rut !== undefined) {
    reportInput.rut = options.rut;
  }
  if (options.name !== undefined) {
    reportInput.name = options.name;
  }
  if (options.dkimSelectors !== undefined) {
    reportInput.dkimSelectors = options.dkimSelectors;
  }
  if (options.timeoutMs !== undefined) {
    reportInput.timeoutMs = options.timeoutMs;
  }

  const report = await buildRiskCheckReport(reportInput);

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(renderTextReport(report));
  }

  return 0;
}

export function usage(): string {
  return [
    'reizan-oiv-risk-check',
    '',
    'Self-assessment CLI for a Chilean entity assessing its own domain.',
    '',
    'Usage:',
    '  reizan-oiv-risk-check --domain example.cl --self-attest',
    '  reizan-oiv-risk-check --rut 97006000-6',
    '  reizan-oiv-risk-check --rut 97006000-6 --domain example.cl --self-attest --json',
    '',
    'Options:',
    '  --domain <domain>             Own apex domain to assess',
    '  --rut <rut>                   Chilean RUT to check in anci-oiv-resolver',
    '  --name <razon-social>         Optional name for resolver heuristic fallback',
    '  --json                        Print machine-readable JSON',
    '  --self-attest                 Required before any domain posture assessment',
    '  --i-own-this-domain           Alias for --self-attest',
    '  --dkim-selectors <csv>        Override passive DKIM selectors to check',
    '  --timeout-ms <ms>             DNS/fetch timeout per check (default 5000)',
    '  --help                        Show this help',
    '  --version                     Show version',
    '',
    'Ethical line:',
    '  Use only for domains controlled by the running entity. The tool performs passive DNS lookups and minimal HTTPS fetches; it never performs port scanning.'
  ].join('\n');
}

function splitArg(arg: string): { flag: string; inlineValue?: string } {
  const equalsIndex = arg.indexOf('=');
  if (equalsIndex < 0) {
    return { flag: arg };
  }

  return {
    flag: arg.slice(0, equalsIndex),
    inlineValue: arg.slice(equalsIndex + 1)
  };
}

function readValue(argv: string[], index: number, inlineValue: string | undefined, flag: string): string {
  if (inlineValue !== undefined) {
    if (inlineValue.length === 0) {
      throw new CliError(`${flag} requires a value`);
    }
    return inlineValue;
  }

  const next = argv[index + 1];
  if (next === undefined || next.startsWith('--')) {
    throw new CliError(`${flag} requires a value`);
  }

  return next;
}

function wantsJson(argv: string[]): boolean {
  return argv.includes('--json');
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void runCli(process.argv.slice(2)).then(
    (exitCode) => {
      process.exitCode = exitCode;
    },
    (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      const exitCode = error instanceof CliError ? error.exitCode : 1;
      if (wantsJson(process.argv.slice(2))) {
        console.error(JSON.stringify({ error: message }, null, 2));
      } else {
        console.error(`Error: ${message}`);
      }
      process.exitCode = exitCode;
    }
  );
}
