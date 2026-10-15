// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-3652: no third-party SIEM vendor name in web text. "HEC" (HTTP Event
// Collector) is fine; the vendor name is not. This guard scans every .ts /
// .tsx / .json file under src/ (test files excluded) and fails on any
// case-insensitive "splunk" that is not a wire literal the protocol or a
// sender's config requires: the `Authorization: Splunk <token>` scheme, the
// `X-Splunk-Request-Channel` header, `splunk_hec*` identifiers and
// source types, and sender config keys (Fluent Bit `Name splunk` /
// `Splunk_Token`, the OTel `com.splunk.*` attributes).
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;

const VENDOR = /splunk/gi;

// Each pattern covers the "splunk" occurrences it matches; anything left is a hit.
const WIRE_LITERALS: RegExp[] = [
  /Authorization: Splunk\b/g, // HEC auth scheme in snippets/docs
  /\bSplunk (?:<token>|\$\w+|\{\{\s*token\s*\}\})/g, // the scheme as a bare header value
  /X-Splunk-Request-Channel/gi, // HEC channel header
  /\bsplunk_hec\w*/g, // snake_case identifiers: splunk_hec, splunk_hec_logs, splunk_hec_ingest, splunk_hec_route
  /\bSplunkHec\w*/g, // PascalCase identifiers, if any remain
  /\bName\s+splunk\b/g, // Fluent Bit output plugin name
  /\bSplunk_Token\b/g, // Fluent Bit output config key
  /\bcom\.splunk\.\w+/g, // OTel splunk_hec exporter attribute names
  /\/\(\^\|_\)splunk\//g, // helpers.ts: transport inference over third-party parser file names
];

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|json)$/.test(name) && !/\.test\.[^.]+$/.test(name)) out.push(p);
  }
  return out;
}

function findVendorText(src: string): string[] {
  const hits: string[] = [];
  src.split('\n').forEach((line, i) => {
    let rest = line;
    for (const re of WIRE_LITERALS) rest = rest.replace(re, '');
    VENDOR.lastIndex = 0;
    if (VENDOR.test(rest)) hits.push(`${i + 1}: ${line.trim().slice(0, 160)}`);
  });
  return hits;
}

describe('no vendor SIEM name in web text (NAN-3652)', () => {
  it('flags prose and allows wire literals', () => {
    expect(findVendorText(`label: 'Splunk HEC'`)).toHaveLength(1);
    expect(findVendorText(`// the way a Splunk real-time search keeps running`)).toHaveLength(1);
    expect(findVendorText(`"title": "Cribl Stream: Splunk HEC destination"`)).toHaveLength(1);
    expect(findVendorText(`-H 'Authorization: Splunk $HEC_TOKEN'`)).toHaveLength(0);
    expect(findVendorText(`headers: [{ key: 'Authorization', value: 'Splunk <token>' }]`)).toHaveLength(0);
    expect(findVendorText(`case 'splunk_hec': type = "splunk_hec_logs" splunk_hec/nano`)).toHaveLength(0);
    expect(findVendorText(`X-Splunk-Request-Channel: abc`)).toHaveLength(0);
    // A wire literal on the line does not excuse prose next to it.
    expect(findVendorText(`'Splunk HEC: Authorization: Splunk <token>'`)).toHaveLength(1);
  });

  it('never shows the vendor name in nanosiem-web/src', () => {
    const offenders: string[] = [];
    for (const file of walk(ROOT, [])) {
      const rel = relative(ROOT, file);
      for (const hit of findVendorText(readFileSync(file, 'utf8'))) offenders.push(`${rel}:${hit}`);
    }
    expect(offenders, 'say "HEC", not the vendor name (NAN-3652)').toEqual([]);
  });
});
