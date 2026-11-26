#!/usr/bin/env node
// spf-check: count the DNS lookups in a domain's SPF record (RFC 7208 limit: 10),
// show where they come from, and print a flattened preview. No dependencies (Node 18+).
// Usage: node spf-check.mjs example.com [--flatten] [--json]
import { promises as dns } from 'node:dns';

const LOOKUP_LIMIT = 10;
const VOID_LIMIT = 2;
const MX_LIMIT = 10;

const args = process.argv.slice(2);
const domain = args.find((a) => !a.startsWith('--'));
const wantFlatten = args.includes('--flatten');
const wantJson = args.includes('--json');
if (!domain) {
  console.error('Usage: node spf-check.mjs example.com [--flatten] [--json]');
  process.exit(2);
}

const state = { lookups: 0, voids: 0, warnings: [], ip4: new Set(), ip6: new Set(), keep: [] };

function isVoid(err) {
  return err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA');
}

async function txtSpf(name) {
  let records;
  try {
    records = (await dns.resolveTxt(name)).map((parts) => parts.join(''));
  } catch (err) {
    if (isVoid(err)) return { void: true, record: null };
    throw err;
  }
  const spf = records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (spf.length > 1) state.warnings.push(`${name} has ${spf.length} SPF records (must be exactly one: permerror)`);
  return { void: spf.length === 0 && records.length === 0, record: spf[0] ?? null };
}

async function addresses(name, cidr4, cidr6) {
  const out = { v4: [], v6: [] };
  for (const [type, key, cidr] of [['A', 'v4', cidr4], ['AAAA', 'v6', cidr6]]) {
    try {
      const res = type === 'A' ? await dns.resolve4(name) : await dns.resolve6(name);
      out[key] = res.map((ip) => (cidr ? `${ip}/${cidr}` : ip));
    } catch (err) {
      if (!isVoid(err)) throw err;
    }
  }
  return out;
}

function countLookup(node, what) {
  state.lookups += 1;
  node.lookups += 1;
  node.terms.push(what);
}

function splitDomainCidr(value, fallback) {
  // a:host/24//64, mx/24, a//64
  const m = /^([^/]*)(?:\/(\d+))?(?:\/\/(\d+))?$/.exec(value ?? '');
  if (!m) return { host: fallback, c4: null, c6: null };
  return { host: m[1] || fallback, c4: m[2] ?? null, c6: m[3] ?? null };
}

async function walk(name, depth, node) {
  if (depth > 12) {
    state.warnings.push(`include chain too deep at ${name}`);
    return;
  }
  const { record, void: isVoidRecord } = await txtSpf(name);
  if (!record) {
    if (isVoidRecord) state.voids += 1;
    state.warnings.push(`${name}: no SPF record found${depth === 0 ? '' : ' (include/redirect target: permerror)'}`);
    return;
  }
  node.record = record;
  const terms = record.trim().split(/\s+/).slice(1);
  let redirect = null;
  let all = null;
  for (const raw of terms) {
    const t = raw.toLowerCase();
    if (t.startsWith('redirect=')) { redirect = raw.slice(9); continue; }
    if (t.startsWith('exp=') || t === '') continue;
    const q = /^[+\-~?]/.test(raw) ? raw[0] : '+';
    const body = /^[+\-~?]/.test(raw) ? raw.slice(1) : raw;
    const [mech, ...rest] = body.split(/[:]/);
    const value = rest.join(':');
    const m = mech.toLowerCase().replace(/\/.*$/, '');
    if (body.includes('%{')) state.warnings.push(`${name}: "${raw}" uses a macro and can't be flattened`);
    switch (m) {
      case 'all':
        all = q;
        break;
      case 'ip4':
        if (q === '+') state.ip4.add(value); else if (depth === 0) state.keep.push(raw);
        break;
      case 'ip6':
        if (q === '+') state.ip6.add(value); else if (depth === 0) state.keep.push(raw);
        break;
      case 'include': {
        countLookup(node, `include:${value}`);
        const child = { name: value, lookups: 0, terms: [], children: [] };
        node.children.push(child);
        if (q !== '+') {
          state.warnings.push(`${name}: "${raw}" has a non-pass qualifier; kept as-is when flattening`);
          if (depth === 0) state.keep.push(raw);
        }
        if (value.includes('%{')) break;
        await walk(value, depth + 1, child);
        break;
      }
      case 'a': {
        const { host, c4, c6 } = splitDomainCidr(body.slice(1).replace(/^:/, ''), name);
        countLookup(node, raw);
        const ips = await addresses(host, c4, c6);
        if (!ips.v4.length && !ips.v6.length) state.voids += 1;
        if (q === '+') { ips.v4.forEach((i) => state.ip4.add(i)); ips.v6.forEach((i) => state.ip6.add(i)); } else if (depth === 0) state.keep.push(raw);
        break;
      }
      case 'mx': {
        const { host, c4, c6 } = splitDomainCidr(body.slice(2).replace(/^:/, ''), name);
        countLookup(node, raw);
        let hosts = [];
        try { hosts = (await dns.resolveMx(host)).map((r) => r.exchange); } catch (err) { if (!isVoid(err)) throw err; }
        if (!hosts.length) state.voids += 1;
        if (hosts.length > MX_LIMIT) state.warnings.push(`${name}: "${raw}" returns ${hosts.length} MX hosts (limit ${MX_LIMIT}: permerror)`);
        for (const h of hosts.slice(0, MX_LIMIT)) {
          const ips = await addresses(h, c4, c6);
          if (q === '+') { ips.v4.forEach((i) => state.ip4.add(i)); ips.v6.forEach((i) => state.ip6.add(i)); }
        }
        if (q !== '+' && depth === 0) state.keep.push(raw);
        break;
      }
      case 'ptr':
        countLookup(node, raw);
        state.warnings.push(`${name}: "ptr" is deprecated (RFC 7208 5.5) and can't be flattened`);
        if (depth === 0) state.keep.push(raw);
        break;
      case 'exists':
        countLookup(node, raw);
        state.warnings.push(`${name}: "${raw}" can't be flattened; kept as-is`);
        if (depth === 0) state.keep.push(raw);
        break;
      default:
        state.warnings.push(`${name}: unknown term "${raw}"`);
    }
  }
  if (redirect && all === null) {
    countLookup(node, `redirect=${redirect}`);
    const child = { name: redirect, lookups: 0, terms: [], children: [], redirect: true };
    node.children.push(child);
    await walk(redirect, depth + 1, child);
    if (depth === 0) node.redirectAll = child.all;
  }
  node.all = all;
}

function printTree(node, indent = '') {
  const total = subtotal(node);
  console.log(`${indent}${node.name}  (${total} lookup${total === 1 ? '' : 's'})`);
  for (const c of node.children) printTree(c, indent + '  ');
}
function subtotal(node) {
  return node.lookups + node.children.reduce((s, c) => s + subtotal(c), 0);
}

function flattenedRecords(root) {
  const allQ = root.all ?? root.redirectAll ?? '~';
  const mechs = [...state.keep, ...[...state.ip4].map((i) => `ip4:${i}`), ...[...state.ip6].map((i) => `ip6:${i}`)];
  const single = `v=spf1 ${mechs.join(' ')} ${allQ}all`;
  if (single.length <= 450) return { main: single, parts: [] };
  // Split into chained records of <= 450 characters; each costs one include lookup.
  const parts = [];
  let cur = [];
  for (const m of mechs) {
    if (`v=spf1 ${[...cur, m].join(' ')}`.length > 440) { parts.push(cur); cur = []; }
    cur.push(m);
  }
  if (cur.length) parts.push(cur);
  const names = parts.map((_, i) => `_spf${i + 1}.${root.name}`);
  return {
    main: `v=spf1 ${names.map((n) => `include:${n}`).join(' ')} ${allQ}all`,
    parts: parts.map((p, i) => ({ name: names[i], record: `v=spf1 ${p.join(' ')}` })),
  };
}

const root = { name: domain.toLowerCase(), lookups: 0, terms: [], children: [] };
try {
  await walk(root.name, 0, root);
} catch (err) {
  console.error(`DNS error: ${err.code ?? err.message}`);
  process.exit(3);
}

const over = state.lookups > LOOKUP_LIMIT;
const voidOver = state.voids > VOID_LIMIT;
const result = {
  domain: root.name,
  record: root.record ?? null,
  lookups: state.lookups,
  limit: LOOKUP_LIMIT,
  voidLookups: state.voids,
  status: !root.record ? 'none' : over || voidOver ? 'permerror' : 'ok',
  warnings: state.warnings,
};
if (wantFlatten && root.record) result.flattened = flattenedRecords(root);

if (wantJson) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(`SPF record: ${result.record ?? '(none)'}`);
  console.log(`DNS lookups: ${state.lookups} / ${LOOKUP_LIMIT}${over ? '  <-- OVER THE LIMIT: receivers return permerror and SPF fails' : ''}`);
  if (voidOver) console.log(`Void lookups: ${state.voids} (limit ${VOID_LIMIT}): permerror`);
  if (root.record) { console.log(''); printTree(root); }
  if (state.warnings.length) { console.log('\nWarnings:'); state.warnings.forEach((w) => console.log(`  - ${w}`)); }
  if (result.flattened) {
    console.log('\nFlattened preview (a snapshot: providers change their IPs, so a static copy goes stale):');
    console.log(`  ${root.name} TXT "${result.flattened.main}"`);
    for (const p of result.flattened.parts) console.log(`  ${p.name} TXT "${p.record}"`);
    console.log('  Note: TXT strings over 255 characters must be split into several quoted strings in one record.');
  }
}
process.exit(result.status === 'permerror' ? 1 : 0);
