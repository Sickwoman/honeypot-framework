#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');

const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';
const VT_URL = 'https://www.virustotal.com/api/v3/ip_addresses';

function printHelp() {
  console.log(`Advanced Threat Intelligence Enricher

Usage:
  node threatintel/advanced-threat-intel.js --ip 8.8.8.8
  node threatintel/advanced-threat-intel.js --ips-file ips.txt
  node threatintel/advanced-threat-intel.js --alert-file alert.json --output enriched-alert.json

Options:
  --ip <ip>            Single IP to enrich
  --ips-file <file>    Text file containing one IP per line
  --alert-file <file>  JSON alert or array of alerts to enrich
  --output <file>      Output file for the enriched result
  --help               Show this help

Environment:
  ABUSEIPDB_API_KEY    Required for AbuseIPDB enrichment
  VT_API_KEY           Required for VirusTotal enrichment
`);
}

function getArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg === '--ip') {
      args.ip = argv[++i];
    } else if (arg === '--ips-file') {
      args.ipsFile = argv[++i];
    } else if (arg === '--alert-file') {
      args.alertFile = argv[++i];
    } else if (arg === '--output') {
      args.output = argv[++i];
    }
  }
  return args;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function normalizeSeverity(score) {
  if (score >= 85) return 'CRITICAL';
  if (score >= 70) return 'HIGH';
  if (score >= 45) return 'MEDIUM';
  if (score >= 20) return 'LOW';
  return 'SAFE';
}

function requestJson(url, headers) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method: 'GET', headers }, (response) => {
      let body = '';

      response.on('data', (chunk) => {
        body += chunk;
      });

      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(`HTTP ${response.statusCode}: ${body || 'request failed'}`));
          return;
        }

        try {
          resolve(JSON.parse(body || '{}'));
        } catch (error) {
          reject(new Error(`Unable to parse JSON response: ${error.message}`));
        }
      });
    });

    request.on('error', reject);
    request.end();
  });
}

async function queryAbuseIPDB(ip, apiKey) {
  const params = new URLSearchParams({
    ipAddress: ip,
    maxAgeInDays: '90',
    verbose: '',
  });

  const response = await requestJson(`${ABUSEIPDB_URL}?${params.toString()}`, {
    'Key': apiKey,
    'Accept': 'application/json',
  });

  const data = response && response.data ? response.data : {};
  return {
    provider: 'abuseipdb',
    confidence_score: Number(data.abuseConfidenceScore || 0),
    total_reports: Number(data.totalReports || 0),
    last_reported_at: data.lastReportedAt || null,
    is_blacklisted: Boolean(data.isBlacklisted),
    is_whitelisted: Boolean(data.isWhitelisted),
    country: data.countryCode || 'Unknown',
    usage_type: data.usageType || 'Unknown',
    isp: data.isp || 'Unknown',
    domain: data.domain || 'Unknown',
    reports: Array.isArray(data.reports) ? data.reports.slice(0, 5) : [],
  };
}

async function queryVirusTotal(ip, apiKey) {
  const response = await requestJson(`${VT_URL}/${ip}`, {
    'x-apikey': apiKey,
    'Accept': 'application/json',
  });

  const attributes = response && response.data && response.data.attributes ? response.data.attributes : {};
  const stats = attributes.last_analysis_stats || {};

  return {
    provider: 'virustotal',
    reputation: Number(attributes.reputation || 0),
    last_analysis_stats: stats,
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    timeout: Number(stats.timeout || 0),
  };
}

function calculateRiskScore(abuseData, vtData) {
  let score = 0;

  if (abuseData) {
    score += (abuseData.confidence_score || 0) * 0.65;
    score += clamp((abuseData.total_reports || 0) * 0.65, 0, 30);
    if (abuseData.is_blacklisted) score += 18;
    if (abuseData.is_whitelisted) score -= 15;
  }

  if (vtData) {
    score += (vtData.reputation || 0) * 0.35;
    score += (vtData.malicious || 0) * 4;
    score += (vtData.suspicious || 0) * 2;
  }

  return clamp(Math.round(score), 0, 100);
}

function createThreatIntelSummary(ip, abuseData, vtData) {
  const score = calculateRiskScore(abuseData, vtData);
  const severity = normalizeSeverity(score);
  const indicators = [];

  if (abuseData && abuseData.is_blacklisted) indicators.push('blacklisted');
  if (abuseData && (abuseData.confidence_score || 0) >= 75) indicators.push('high_abuse_confidence');
  if (vtData && (vtData.malicious || 0) > 0) indicators.push('malicious_vt_signal');
  if (abuseData && abuseData.total_reports > 0) indicators.push('reported_in_community');

  return {
    ip,
    threat_score: score,
    threat_level: severity,
    threat_indicators: indicators,
    providers: {
      abuseipdb: abuseData || null,
      virustotal: vtData || null,
    },
    last_updated: new Date().toISOString(),
  };
}

async function enrichSingleIp(ip, config) {
  const result = {
    ip,
    checked_at: new Date().toISOString(),
    threat_intel: null,
  };

  const abuseCheck = config.abuseipdbApiKey ? await queryAbuseIPDB(ip, config.abuseipdbApiKey).catch(() => null) : null;
  const vtCheck = config.virusTotalApiKey ? await queryVirusTotal(ip, config.virusTotalApiKey).catch(() => null) : null;

  result.threat_intel = createThreatIntelSummary(ip, abuseCheck, vtCheck);
  return result;
}

async function enrichAlert(alert, config) {
  if (!alert || !alert.source_ip) {
    return alert;
  }

  const intel = await enrichSingleIp(alert.source_ip, config);
  const threatIntel = intel.threat_intel;

  return {
    ...alert,
    threat_score: threatIntel.threat_score,
    threat_level: threatIntel.threat_level,
    threat_indicators: Array.from(new Set([...(alert.threat_indicators || []), ...threatIntel.threat_indicators])),
    metadata: {
      ...(alert.metadata || {}),
      threat_intel: threatIntel,
    },
  };
}

async function main() {
  const args = getArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const config = {
    abuseipdbApiKey: process.env.ABUSEIPDB_API_KEY || '',
    virusTotalApiKey: process.env.VT_API_KEY || '',
  };

  if (!args.ip && !args.ipsFile && !args.alertFile) {
    printHelp();
    process.exit(1);
  }

  try {
    if (args.ip) {
      const result = await enrichSingleIp(args.ip, config);
      if (args.output) {
        fs.writeFileSync(args.output, JSON.stringify(result, null, 2));
      } else {
        console.log(JSON.stringify(result, null, 2));
      }
      return;
    }

    if (args.ipsFile) {
      const fileContents = fs.readFileSync(args.ipsFile, 'utf8');
      const ips = fileContents.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      const results = [];
      for (const ip of ips) {
        results.push(await enrichSingleIp(ip, config));
      }

      if (args.output) {
        fs.writeFileSync(args.output, JSON.stringify(results, null, 2));
      } else {
        console.log(JSON.stringify(results, null, 2));
      }
      return;
    }

    if (args.alertFile) {
      const raw = fs.readFileSync(args.alertFile, 'utf8');
      const parsed = JSON.parse(raw);
      const alerts = Array.isArray(parsed) ? parsed : [parsed];
      const enriched = [];

      for (const alert of alerts) {
        enriched.push(await enrichAlert(alert, config));
      }

      if (args.output) {
        fs.writeFileSync(args.output, JSON.stringify(enriched.length === 1 ? enriched[0] : enriched, null, 2));
      } else {
        console.log(JSON.stringify(enriched.length === 1 ? enriched[0] : enriched, null, 2));
      }
    }
  } catch (error) {
    console.error(`Threat intel enrichment failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  queryAbuseIPDB,
  queryVirusTotal,
  calculateRiskScore,
  enrichSingleIp,
  enrichAlert,
  createThreatIntelSummary,
};
