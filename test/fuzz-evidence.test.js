'use strict';

/**
 * Differential fuzzing of the verifier.
 *
 * A real world (test/world.js: a public git repository, a registry, a
 * running process, an attester configuration) produces evidence that
 * appraises as `pass`.  Each iteration applies one semantic mutation to a
 * copy of that evidence, recomputes the evidence digest (root on a server
 * without hardware attestation can always do that; only a TPM quote or a
 * confidential VM report binds it), and appraises the mutant.
 *
 * The oracle, per mutant:
 *
 *   equivalent   canonically equal to the original (keys reordered):
 *                must pass, exactly as the original did
 *   neutral      differs only in a field the verifier deliberately does
 *                not judge (see NEUTRAL, each with its reason): any status
 *   relevant     everything else: must NOT pass
 *
 * and for every mutant: appraisal never throws, never hangs (a per-mutant
 * timeout), and the report renders.
 *
 * Deterministic by default (FUZZ_SEED, FUZZ_ITERATIONS); a longer run:
 *   FUZZ_ITERATIONS=5000 FUZZ_SEED=7 node --test test/fuzz-evidence.test.js
 * or of one targeted class (see TARGETED):
 *   FUZZ_CLASS=file-rename FUZZ_ITERATIONS=2000 node --test test/fuzz-evidence.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {Tpm, util, evidence: evidenceFormat} = require('attestium');
const {createWorld} = require('./world');
const {
  git, sha256, writeFiles, hasTpmSimulator, startSwtpm, imaEntry, extendImaLog,
} = require('./helpers');
const {normalizeVerifierConfig, loadAttesterConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');
const {markdown} = require('../lib/report');
const {undocumented} = require('./documented-findings');

const linux = process.platform === 'linux';
const ITERATIONS = Number(process.env.FUZZ_ITERATIONS || 1200);
const SEED = Number(process.env.FUZZ_SEED || 20_260_930);
const TIMEOUT = 20_000;
// One targeted mutation class only (a long run of it), by name.
const TARGETED_ONLY = process.env.FUZZ_CLASS;

// ─── deterministic randomness ─────────────────────────────────────────

function random(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6D_2B_79_F5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4_294_967_296;
  };

  next.int = n => Math.floor(next() * n);
  next.pick = list => list[next.int(list.length)];
  return next;
}

// ─── paths into the evidence ──────────────────────────────────────────

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const children = value => (Array.isArray(value) ? value.map((_, index) => index) : (isObject(value) ? Object.keys(value) : []));

function getAt(root, keys) {
  return keys.reduce((value, key) => value[key], root);
}

/** A random path: a walk from the root that stops at some depth. */
function randomPath(root, rng) {
  const keys = [];
  let value = root;
  for (;;) {
    const options = children(value).filter(key => !(keys.length === 0 && key === 'evidenceDigest'));
    if (options.length === 0 || (keys.length > 0 && rng() < 0.3)) {
      return keys;
    }

    const key = rng.pick(options);
    keys.push(key);
    value = value[key];
  }
}

/** The path as a pattern: array indices and the keys of file maps become `*`. */
function pattern(keys) {
  const maps = new Set(['files', 'other', 'generated']);
  return keys.map((key, index) => (typeof key === 'number' || maps.has(keys[index - 1]) ? '*' : key)).join('.');
}

// ─── the oracle ───────────────────────────────────────────────────────

/**
 * Fields the verifier deliberately does not judge in this world, with why.
 * A mutation there may pass.  Anything not listed must not.
 */
const NEUTRAL = [
  [/^host\./, 'host details are reported, not verified (the distribution archive is off here)'],
  [/^attester\.(platform|arch|node|executable\.path)$/, 'the attester is judged by its executable\'s hash and version'],
  [/^distro$|^distro\./, 'distribution checks are off in this configuration'],
  [/^(tpm|ima|confidential)(\.|$)/, 'no hardware is configured; only `required` flags matter (checked by targeted mutations)'],
  [/^services\.\*\.root$/, 'the verifier uses realRoot'],
  [/^services\.\*\.git\.ref$/, 'the commit is verified, not the ref name'],
  [/^services\.\*\.fileCount$/, 'a count; the file map is what is compared'],
  [/^services\.\*\.userProcesses(\.|$)/, 'programs outside the service are listed, not inspected'],
  [/^services\.\*\.processes\.\*\.(pid|ppid|uid|cwd|startTime|cmdline|runtime)(\.|$)/, 'process metadata: the attester\'s runtime checks judge it and report findings'],
  [/^services\.\*\.processes\.\*\.integrity\.(passed|libraries|memorySummary|executablePages|linker|tracer|suspiciousFds|listening)(\.|$)/, 'the attester\'s measurements behind integrity.findings, which the verifier judges'],
  [/^services\.\*\.installs\.\*\.packages\.\*\.fileCount$/, 'a count; the digest is compared'],
  [/^globalPackages\.packages\.\*\.fileCount$/, 'a count; the digest is compared'],
  [/^executables\.\*\.size$/, 'a size; the hash is compared'],
  [/^services\.\*\.realRoot$/, 'the root the server reports is used as reported unless services[].root pins it (not pinned here)'],
  [/^executables\.\*\.deleted$/, 'a label; the process\'s exeDeleted is judged, and the hash is of the running copy'],
  [/^globalPackages\.packages\.\*\.name$/, 'npm and corepack come with Node.js and are identified by their path and version; the digest covers their package.json'],
  [/^services\.\*\.installs\.\*\.dir$/, 'where the packages were found; they are compared with the lockfile wherever they are'],
  [/^globalPackages\.dir$/, 'locates global package files only to explain executables by hash; none of them runs here'],
  [/^(services\.\*\.installs\.\*|globalPackages)\.packages\.\*\.path$/, 'where a package is installed; its content is compared by name, version and digest, and its files explain only equal hashes'],
];

/** Lists whose order and repetition carry no meaning (the command line's do). */
const SETS = /^(executables|libraries|services\.\*\.(processes|userProcesses|installs|errors)|services\.\*\.installs\.\*\.(packages|unaccounted|links|caches|errors)|services\.\*\.processes\.\*\.integrity\.(findings|incomplete|libraries)|globalPackages\.(packages|links|caches|errors))$/;

/**
 * Documented behavior that lets a mutation pass although it matters; each
 * is reported rather than fixed here (see the reason).
 */
// Mutations the verifier accepts, as documented; none at present.
const KNOWN = [];

function neutralReason(keys, op) {
  const text = pattern(keys);
  if ((op === 'reverse' || op === 'duplicate') && SETS.test(text)) {
    return 'a set: order and repeated entries do not change it';
  }

  if ((op === 'delete' || op === 'drop' || op === 'retype-empty-array') && /^globalPackages(\.packages(\.\*)?)?$/.test(text)) {
    return 'an omission: the global packages section lists what the attester found, and nothing else refers to it';
  }

  if ((op === 'delete' || op === 'drop') && /^services\.\*\.installs\.\*\.packages(\.\*)?$/.test(text)) {
    return 'an omission: a package in the lockfile need not be installed (optional and other platforms\' packages); files outside any package are reported as unaccounted';
  }

  if ((op === 'delete' || op.startsWith('rekey')) && /packages\.\*\.files$/.test(text)) {
    return 'an omission: a verified package\'s file list only explains executables, and fewer explanations cannot pass more';
  }

  if ((op === 'delete' || op === 'drop') && /^globalPackages(\.packages(\.\*)?)?$/.test(text)) {
    return 'an omission: the global packages section lists what the attester found, and nothing else refers to it';
  }

  if (op === 'unknown-key' || op === 'proto' || op === 'constructor') {
    return 'an unknown key the verifier ignores (the schema allows it here); prototype pollution is checked separately';
  }

  const match = [...NEUTRAL, ...KNOWN].find(([regex]) => regex.test(text));
  return match ? match[1] : null;
}

/** Files of the world's deploy that its .gitignore ignores. */
const IGNORED = new Set(['.env', 'build/app.js']);

const canonical = evidence => {
  const {tpm, ima, confidential, ...rest} = evidence;
  return util.canonicalize({...rest, hardware: {tpm, ima, confidential}});
};

// ─── mutations ────────────────────────────────────────────────────────

const HEX = /^[\da-f]+$/;
function flipNibble(text, rng) {
  const index = rng.int(text.length);
  const digit = Number.parseInt(text[index], 16);
  return `${text.slice(0, index)}${((digit + 1 + rng.int(15)) % 16).toString(16)}${text.slice(index + 1)}`;
}

const STRING_EDITS = [
  ['nibble', (text, rng) => (HEX.test(text) && text.length > 0 ? flipNibble(text, rng) : `${text}0`)],
  ['upper', text => (text.toUpperCase() === text ? `${text}X` : text.toUpperCase())],
  ['dot-slash', text => `./${text}`],
  ['double-slash', text => (text.includes('/') ? text.replace('/', '//') : `${text}//x`)],
  ['dot-dot', text => `${text}/../${path.posix.basename(text) || 'x'}`],
  ['trailing-slash', text => `${text}/`],
  ['nul', text => `${text}\0`],
  ['nfd', text => `${text}é`],
  ['nfc', text => `${text}é`],
  ['space', text => `${text} `],
  ['empty', () => ''],
  ['long', text => text.repeat(1 + Math.ceil(10_000 / Math.max(1, text.length)))],
];

function retype(value, rng) {
  const options = [
    ['string', () => String(isObject(value) || Array.isArray(value) ? JSON.stringify(value) : value)],
    ['number', () => (typeof value === 'string' && HEX.test(value) ? Number.parseInt(value.slice(0, 8), 16) : 1)],
    ['null', () => null],
    ['boolean', () => true],
    ['array', () => [value]],
    ['empty-array', () => []],
    ['object', () => ({value})],
    ['empty-object', () => ({})],
  ];
  const kind = Array.isArray(value) ? 'array' : (value === null ? 'null' : typeof value);
  const [name, make] = rng.pick(options.filter(([name]) => !name.endsWith(kind) || (name === 'empty-array' && value.length > 0)));
  return {name: `retype-${name}`, value: make()};
}

function setOwnKey(object, key, value) {
  Object.defineProperty(object, key, {
    value, enumerable: true, writable: true, configurable: true,
  });
}

/**
 * One random structural mutation at a random path.
 * @returns {{op: string, keys: Array}} (applied to evidence in place)
 */
function mutateAt(evidence, rng) {
  const keys = randomPath(evidence, rng);
  const parent = keys.length > 0 ? getAt(evidence, keys.slice(0, -1)) : null;
  const key = keys.at(-1);
  const value = getAt(evidence, keys);
  const ops = [];
  if (parent) {
    ops.push('delete', 'retype');
  }

  if (typeof value === 'string') {
    ops.push('string', 'string', 'string');
  }

  if (typeof value === 'number') {
    ops.push('number');
  }

  if (typeof value === 'boolean') {
    ops.push('flip');
  }

  if (Array.isArray(value) && value.length > 0) {
    ops.push('duplicate', 'drop', 'reverse');
  }

  if (isObject(value)) {
    ops.push('proto', 'constructor', 'unknown-key', 'rekey', 'reorder', 'reorder');
  }

  const op = rng.pick(ops);
  const set = next => {
    parent[key] = next;
  };

  switch (op) {
    case 'delete': {
      if (Array.isArray(parent)) {
        parent.splice(key, 1);
      } else {
        delete parent[key];
      }

      return {op, keys};
    }

    case 'retype': {
      const {name, value: next} = retype(value, rng);
      set(next);
      return {op: name, keys};
    }

    case 'string': {
      const [name, edit] = rng.pick(STRING_EDITS);
      const next = edit(value, rng);
      if (parent) {
        set(next);
      }

      return {op: `string-${name}`, keys, changed: next !== value};
    }

    case 'number': {
      const next = rng.pick([value + 1, value - 1, 0, -value, 2 ** 53, 1e21, value + 0.5]);
      set(next);
      return {op: 'number', keys, changed: next !== value};
    }

    case 'flip': {
      set(!value);
      return {op, keys};
    }

    case 'duplicate': {
      value.push(structuredClone(value[rng.int(value.length)]));
      return {op, keys};
    }

    case 'drop': {
      value.splice(rng.int(value.length), 1);
      return {op, keys};
    }

    case 'reverse': {
      value.reverse();
      return {op, keys};
    }

    case 'proto':
    case 'constructor': {
      setOwnKey(value, op === 'proto' ? '__proto__' : 'constructor', rng.pick([{}, 'x', {polluted: true}, null]));
      return {op, keys};
    }

    case 'unknown-key': {
      value[`x-${rng.int(1000)}`] = rng.pick([1, 'x', null, {}, []]);
      return {op, keys};
    }

    case 'rekey': {
      const names = Object.keys(value);
      if (names.length === 0) {
        value.x = 1;
        return {op, keys};
      }

      const old = rng.pick(names);
      const [edit, change] = rng.pick(STRING_EDITS);
      const renamed = change(old, rng);
      const moved = value[old];
      delete value[old];
      setOwnKey(value, renamed, moved);
      return {op: `rekey-${edit}`, keys: [...keys, old]};
    }

    default: {
      // Reorder the keys: canonically the same evidence.
      const entries = Object.entries(value);
      for (const [name] of entries) {
        delete value[name];
      }

      for (let index = entries.length - 1; index > 0; index--) {
        const other = rng.int(index + 1);
        [entries[index], entries[other]] = [entries[other], entries[index]];
      }

      for (const [name, item] of entries) {
        setOwnKey(value, name, item);
      }

      return {op: 'reorder', keys};
    }
  }
}

/**
 * Targeted semantic mutations.  Each returns what it did and whether a
 * pass is acceptable (`neutral` with the reason) or not.
 */
const TARGETED = [
  ['nonce-nibble', (evidence, rng) => {
    evidence.nonce = flipNibble(evidence.nonce, rng);
  }],
  ['nonce-case', evidence => {
    evidence.nonce = evidence.nonce.toUpperCase();
  }],
  ['nonce-short', evidence => {
    evidence.nonce = evidence.nonce.slice(0, -1);
  }],
  ['collected-late', (evidence, rng) => {
    // Appraisal happens at a fixed time just after collection (see setupWorld).
    evidence.collectedAt = new Date(Date.parse(evidence.collectedAt) + ((66 + rng.int(3600)) * 1000)).toISOString();
  }],
  ['collected-old', (evidence, rng) => {
    evidence.collectedAt = new Date(Date.parse(evidence.collectedAt) - ((896 + rng.int(86_400)) * 1000)).toISOString();
  }],
  ['collected-jitter', (evidence, rng) => {
    evidence.collectedAt = new Date(Date.parse(evidence.collectedAt) - (rng.int(30) * 1000)).toISOString();
    return 'a timestamp inside the accepted window';
  }],
  ['digest-stale', (evidence, rng) => {
    evidence.services[0].files['index.js'][0] = flipNibble(evidence.services[0].files['index.js'][0], rng);
    return {keepDigest: true};
  }],
  ['digest-case', evidence => ({keepDigest: true, digest: evidence.evidenceDigest.toUpperCase()})],
  ['file-hash', (evidence, rng) => {
    const {files} = evidence.services[0];
    const name = rng.pick(Object.keys(files).filter(file => !file.startsWith('.env') && !file.startsWith('build/')));
    files[name][0] = flipNibble(files[name][0], rng);
  }],
  ['file-hash-case', (evidence, rng) => {
    const {files} = evidence.services[0];
    const name = rng.pick(Object.keys(files).filter(file => !file.startsWith('.env') && !file.startsWith('build/')));
    files[name][0] = files[name][0].toUpperCase();
  }],
  ['file-delete', (evidence, rng) => {
    const {files} = evidence.services[0];
    delete files[rng.pick(Object.keys(files).filter(file => !file.startsWith('.env') && !file.startsWith('build/')))];
  }],
  ['file-add', (evidence, rng) => {
    evidence.services[0].files[rng.pick(['evil.js', 'lib/evil.js', 'node_modules2/x.js', '.hidden.js'])] = [sha256('evil'), '100644'];
  }],
  ['file-rename', (evidence, rng) => {
    const {files} = evidence.services[0];
    const name = rng.pick(Object.keys(files).filter(file => !file.startsWith('.env') && !file.startsWith('build/')));
    const [, edit] = rng.pick(STRING_EDITS.filter(([edit]) => !['nibble', 'upper', 'empty', 'long'].includes(edit)));
    const renamed = edit(name, rng);
    const entry = files[name];
    delete files[name];
    setOwnKey(files, renamed, entry);
    // The original name now missing is itself a difference; keep it
    // present too half the time, so only the added alias differs.
    if (rng() < 0.5) {
      files[name] = entry;
    }
  }],
  ['file-to-other-service', (evidence, rng) => {
    const [service] = evidence.services;
    const other = {
      ...structuredClone(service), name: 'other', files: {}, processes: [], installs: [],
    };
    const name = rng.pick(Object.keys(service.files).filter(file => !file.startsWith('.env') && !file.startsWith('build/')));
    other.files[name] = service.files[name];
    delete service.files[name];
    evidence.services.push(other);
  }],
  ['duplicate-service-tampered', (evidence, rng) => {
    const copy = structuredClone(evidence.services[0]);
    const tamper = rng.pick([
      () => {
        copy.files['index.js'][0] = sha256('evil');
      },
      () => {
        copy.processes[0].integrity.findings.push({severity: 'critical', type: 'LD_PRELOAD set', detail: '/tmp/evil.so'});
      },
      () => {
        copy.truncated = true;
      },
      () => {
        copy.installs[0].packages[0].digest = sha256('evil');
      },
      () => {
        copy.processes[0].integrity.incomplete.push({check: 'maps', error: 'EACCES'});
      },
    ]);
    tamper();
    evidence.services.splice(rng.int(2), 0, copy);
  }],
  ['drop-processes', evidence => {
    evidence.services[0].processes = [];
  }],
  ['truncated', (evidence, rng) => {
    const set = rng.pick([
      () => {
        evidence.services[0].truncated = true;
      },
      () => {
        evidence.services[0].processes[0].changedAfterStartTruncated = true;
      },
      () => {
        evidence.services[0].processes[0].metadataChangedAfterStartTruncated = true;
      },
      () => {
        evidence.services[0].processes[0].changedAfterStart = ['index.js'];
      },
      () => {
        evidence.services[0].errors.push({path: 'lib/util.js', error: 'EACCES'});
      },
      () => {
        evidence.services[0].installs[0].errors.push({path: 'alpha/index.js', error: 'EACCES'});
      },
      () => {
        evidence.services[0].installs[0].unaccounted.push('evil/index.js');
      },
      () => {
        evidence.services[0].installs[0].links.push({path: 'evil', problem: 'outside'});
      },
      () => {
        evidence.globalPackages.errors.push({path: 'pm2/index.js', error: 'EACCES'});
      },
      () => {
        evidence.globalPackages.links.push({path: 'evil', problem: 'outside'});
      },
      () => {
        evidence.services[0].processes[0].integrity.incomplete.push({check: 'maps', error: 'EACCES'});
      },
      () => {
        evidence.services[0].processes[0].exeDeleted = true;
      },
    ]);
    set();
  }],
  ['process-finding', (evidence, rng) => {
    evidence.services[0].processes[0].integrity.findings.push({severity: rng.pick(['critical', 'warning']), type: 'LD_PRELOAD set', detail: '/tmp/evil.so'});
  }],
  ['extra-executable', (evidence, rng) => {
    const target = rng.pick(['executables', 'libraries']);
    const item = structuredClone(evidence[target][0]);
    item.path = rng.pick(['/tmp/evil', `${evidence.services[0].realRoot}/evil.so`, '/usr/lib/evil.so']);
    item.sha256 = sha256('evil');
    delete item.nodeVersion;
    evidence[target].push(item);
  }],
  ['executable-hash', (evidence, rng) => {
    const target = rng.pick(['executables', 'libraries']);
    const item = rng.pick(evidence[target]);
    item.sha256 = rng() < 0.5 ? flipNibble(item.sha256, rng) : item.sha256.toUpperCase();
  }],
  ['executable-path', (evidence, rng) => {
    const target = rng.pick(['executables', 'libraries']);
    const item = rng.pick(evidence[target]);
    const [, edit] = rng.pick(STRING_EDITS.filter(([edit]) => !['empty', 'long'].includes(edit)));
    item.path = edit(item.path, rng);
  }],
  ['node-version', (evidence, rng) => {
    evidence.executables[0].nodeVersion = rng.pick(['v1.2.4', 'v1.2.3 ', 'V1.2.3', 'v01.2.3', null]);
  }],
  ['process-exe-unlisted', evidence => {
    // A process whose executable is not in the executables list.
    evidence.services[0].processes[0].exe = '/tmp/evil';
    evidence.services[0].processes[0].cmdline[0] = '/tmp/evil';
  }],
  ['drop-executables', (evidence, rng) => {
    const target = rng.pick(['executables', 'libraries']);
    evidence[target].splice(rng.int(evidence[target].length), 1);
  }],
  ['require-hardware', (evidence, rng) => {
    if (rng() < 0.5) {
      evidence.tpm = {enabled: false, required: true, reason: 'no TPM'};
    } else {
      evidence.confidential = {available: false, required: true, reason: 'no'};
    }
  }],
  ['package-digest', (evidence, rng) => {
    const item = rng.pick(evidence.services[0].installs[0].packages);
    item.digest = rng() < 0.5 ? flipNibble(item.digest, rng) : item.digest.toUpperCase();
    // Patched and repository packages are compared file by file.
    return item.files ? 'the package is compared file by file (patched, or from a repository archive)' : undefined;
  }],
  ['package-files-unbound', (evidence, rng) => {
    // A package verified by its digest, with a file list that does not match it.
    const item = rng.pick([evidence.services[0].installs[0].packages[0], ...evidence.globalPackages.packages]);
    item.files = {...item.files, 'index.js': sha256('evil'), [rng.pick(['evil.node', 'build/Release/x.node'])]: sha256('evil')};
  }],
  ['package-identity', (evidence, rng) => {
    const item = rng.pick(evidence.services[0].installs[0].packages);
    const field = rng.pick(['name', 'version', 'path']);
    const [, edit] = rng.pick(STRING_EDITS.filter(([edit]) => edit !== 'long'));
    item[field] = edit(item[field], rng);
    return field === 'path' ? 'where a package is installed; its content is compared by name, version and digest' : undefined;
  }],
  ['package-file', (evidence, rng) => {
    const item = rng.pick(evidence.services[0].installs[0].packages.filter(item => item.files));
    const name = rng.pick(Object.keys(item.files));
    if (rng() < 0.5) {
      item.files[name] = flipNibble(item.files[name], rng);
    } else {
      item.files['evil.node'] = sha256('evil');
    }
  }],
  ['global-package', (evidence, rng) => {
    const item = rng.pick(evidence.globalPackages.packages);
    const change = rng.pick(['digest', 'version', 'file']);
    if (change === 'digest') {
      item.digest = flipNibble(item.digest, rng);
    } else if (change === 'version') {
      item.version = '9.9.9';
    } else {
      const name = rng.pick(Object.keys(item.files));
      item.files[name] = flipNibble(item.files[name], rng);
    }
  }],
  ['global-node', (evidence, rng) => {
    evidence.globalPackages.node.version = rng.pick(['v1.2.4', 'v0.0.1']);
  }],
  ['commit', (evidence, rng) => {
    const {git: head} = evidence.services[0];
    head.commit = rng.pick([flipNibble(head.commit, rng), head.commit.toUpperCase(), head.commit.slice(0, 12), '0'.repeat(40)]);
  }],
  ['attester', (evidence, rng) => {
    const change = rng.pick(['hash', 'version', 'name']);
    if (change === 'hash') {
      evidence.attester.executable.sha256 = flipNibble(evidence.attester.executable.sha256, rng);
    } else if (change === 'version') {
      evidence.attester.version = rng.pick(['1.0.3', '1.0.4 ', '../1.0.4', '1.0.4/../1.0.4']);
    } else {
      evidence.attester.name = rng.pick(['Auditstatus', 'auditstatus ', 'other']);
    }
  }],
  ['monitor', (evidence, rng) => {
    evidence.monitor = rng.pick([
      {error: 'no log'},
      {
        since: null, until: null, execs: [], maps: [], truncated: false,
      },
      {
        since: evidence.collectedAt, until: evidence.collectedAt, execs: [{
          path: '/tmp/evil', sha256: sha256('evil'), count: 1, lastSeen: evidence.collectedAt,
        }], maps: [], truncated: false,
      },
    ]);
  }],
];

/** Where two JSON values differ (for reports). */
function difference(a, b, at = '$', out = []) {
  if (out.length > 20) {
    return out;
  }

  if (a === b) {
    return out;
  }

  if (a && b && typeof a === 'object' && typeof b === 'object' && Array.isArray(a) === Array.isArray(b)) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!Object.hasOwn(a, key) || !Object.hasOwn(b, key)) {
        out.push(`${at}.${key}: ${Object.hasOwn(a, key) ? 'removed' : `added ${JSON.stringify(b[key]).slice(0, 120)}`}`);
      } else {
        difference(a[key], b[key], `${at}.${key}`, out);
      }
    }

    return out;
  }

  out.push(`${at}: ${JSON.stringify(a).slice(0, 100)} -> ${JSON.stringify(b).slice(0, 100)}`);
  return out;
}

// ─── the run ──────────────────────────────────────────────────────────

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([promise, new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`appraisal did not finish in ${ms} ms`)), ms);
  })]).finally(() => clearTimeout(timer));
}

async function setupWorld(t, {world, verifier = {}, attester = {}} = {}) {
  world ||= await createWorld(t);
  const config = normalizeVerifierConfig({...world.verifierConfig, ...verifier});
  const references = new References({config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence({...loadAttesterConfig(world.attesterConfig), ...attester}, {nonce});
  // A fixed time just after collection, so a long run does not age the evidence.
  const now = new Date(Date.parse(evidence.collectedAt) + 5000);
  const appraise = candidate => appraiseServer({
    server: config.servers[0], evidence: candidate, nonce, references, now,
  });
  return {
    world, config, references, nonce, evidence, appraise,
  };
}

/**
 * Build one mutant.
 * @returns {{mutant: Object, label: string, expect: 'equivalent'|'neutral'|'relevant', reason?: string}}
 */
function makeMutant(original, rng) {
  const mutant = structuredClone(original);
  let label;
  let expect = 'relevant';
  let reason;
  let keepDigest = false;
  let digest;
  if (TARGETED_ONLY || rng() < 0.5) {
    const [name, apply] = TARGETED_ONLY ? TARGETED.find(([name]) => name === TARGETED_ONLY) : rng.pick(TARGETED);
    const outcome = apply(mutant, rng);
    label = name;
    if (typeof outcome === 'string') {
      expect = 'neutral';
      reason = outcome;
    } else if (outcome) {
      ({keepDigest, digest} = outcome);
    }
  } else {
    const {op, keys, changed} = mutateAt(mutant, rng);
    label = `${op} ${pattern(keys)}`;
    reason = neutralReason(keys, op);
    const removed = op === 'delete' ? getAt(original, keys) : undefined;
    if (removed === false || (Array.isArray(removed) && removed.length === 0)) {
      reason = 'an absent flag means false, an absent list empty';
    }

    const owner = keys.length > 1 ? getAt(original, keys.slice(0, -1)) : null;
    if (/packages\.\*\.digest$/.test(pattern(keys)) && owner && owner.files) {
      reason = 'the package is compared file by file (patched, or from a repository archive)';
    }

    if (pattern(keys).startsWith('services.*.files.*') && IGNORED.has(keys[3])) {
      reason = 'a file the commit ignores is not compared (.gitignore; policy.codePaths is empty here)';
    }

    if (changed === false) {
      expect = 'neutral';
      reason = 'no change';
    } else if (reason) {
      expect = 'neutral';
    }
  }

  if (!keepDigest) {
    try {
      mutant.evidenceDigest = evidenceFormat.evidenceDigest(mutant);
    } catch {}
  } else if (digest) {
    mutant.evidenceDigest = digest;
  }

  // As the transport delivers it: JSON text, parsed (own __proto__ keys included).
  // eslint-disable-next-line unicorn/prefer-structured-clone
  const delivered = JSON.parse(JSON.stringify(mutant));
  let equivalent = false;
  try {
    equivalent = canonical(delivered) === canonical(original);
  } catch {}

  if (equivalent) {
    expect = 'equivalent';
  }

  return {
    mutant: delivered, label, expect, reason,
  };
}

async function fuzz(setup, rng, iterations, {onPass} = {}) {
  const problems = [];
  const counts = {};
  // Every finding, once per severity, check and message.
  const findings = new Map();
  for (let index = 0; index < iterations; index++) {
    const {mutant, label, expect, reason} = makeMutant(setup.evidence, rng);
    let result;
    try {
      result = await withTimeout(setup.appraise(mutant), TIMEOUT);
      markdown({
        type: 'auditstatus-report', version: 2, generatedAt: new Date().toISOString(), verifier: {version: 'x'}, services: [], status: result.status, servers: [result],
      });
    } catch (error) {
      problems.push({
        index, label, problem: `threw: ${error.stack}`, diff: difference(setup.evidence, mutant),
      });
      continue;
    }

    for (const finding of result.findings) {
      findings.set(`${finding.severity}\0${finding.check}\0${finding.message}`, finding);
    }

    if (['polluted', 'value', 'x'].some(name => Object.hasOwn(Object.prototype, name))) {
      problems.push({index, label, problem: 'the prototype of Object was polluted'});
      for (const name of ['polluted', 'value', 'x']) {
        Reflect.deleteProperty(Object.prototype, name);
      }
    }

    const key = `${expect} ${result.status}`;
    counts[key] = (counts[key] || 0) + 1;
    if (expect === 'relevant' && result.status === 'pass') {
      problems.push({
        index, label, problem: 'a relevant mutation passed', diff: difference(setup.evidence, mutant),
      });
    } else if (expect === 'equivalent' && result.status !== 'pass') {
      problems.push({index, label, problem: `an equivalent mutation did not pass: ${JSON.stringify(result.findings.filter(finding => finding.severity !== 'info'))}`});
    } else if (result.status === 'pass' && onPass) {
      onPass({label, reason});
    }
  }

  return {problems, counts, findings: [...findings.values()]};
}

test('fuzzing the evidence: relevant mutations never pass, the verifier never throws or hangs', {skip: !linux, timeout: 30 * 60 * 1000}, async t => {
  const setup = await setupWorld(t);
  const baseline = await setup.appraise(setup.evidence);
  assert.equal(baseline.status, 'pass', JSON.stringify(baseline.findings.filter(finding => finding.severity !== 'info')));

  const passes = new Map();
  const {problems, counts, findings} = await fuzz(setup, random(SEED), ITERATIONS, {
    onPass({label}) {
      passes.set(label, (passes.get(label) || 0) + 1);
    },
  });
  if (process.env.FUZZ_REPORT) {
    fs.writeFileSync(process.env.FUZZ_REPORT, JSON.stringify({counts, passes: Object.fromEntries([...passes].sort()), problems}, null, 2));
  }

  t.diagnostic(`seed ${SEED}, ${ITERATIONS} mutants: ${JSON.stringify(counts)}`);
  assert.deepEqual(problems.map(({index, label, problem}) => `#${index} ${label}: ${problem.slice(0, 500)}`), []);
  // Every finding the mutants produced is described in the documentation.
  assert.deepEqual(undocumented([...baseline.findings, ...findings]).map(text => text.slice(0, 300)), []);
});

test('fuzzing TPM-bound evidence: once a quote binds the digest, no mutation of what it covers passes', {skip: !linux || !hasTpmSimulator, timeout: 30 * 60 * 1000}, async t => {
  const world = await createWorld(t);
  const {tcti} = await startSwtpm(t);
  const tpm = new Tpm({tcti});
  const key = await tpm.createAttestationKey();
  const root = fs.realpathSync(world.deployDir);
  const log = Buffer.concat([imaEntry('boot_aggregate', 'boot'), imaEntry(`${root}/lib/util.js`, fs.readFileSync(path.join(root, 'lib/util.js')))]);
  const imaLog = path.join(world.root, 'ima.log');
  fs.writeFileSync(imaLog, log);
  await extendImaLog(tpm, log);
  const setup = await setupWorld(t, {
    world,
    verifier: {
      servers: [{...world.verifierConfig.servers[0], tpm: {publicKey: key.publicKey, ima: true}}],
      services: [{...world.verifierConfig.services[0], root}],
    },
    attester: {
      tpm: {
        enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [0, 10],
      },
      ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
    },
  });
  const baseline = await setup.appraise(setup.evidence);
  assert.equal(baseline.status, 'pass', JSON.stringify(baseline.findings.filter(finding => finding.severity !== 'info')));
  assert.equal(baseline.level, 'tpm+ima');

  // Everything the digest covers is bound: even fields a software-only
  // appraisal does not judge.  Of the rest, the quote and the IMA log are.
  const covered = evidence => {
    const {evidenceDigest: _digest, tpm: _tpm, ima: _ima, confidential: _confidential, ...rest} = evidence;
    return util.canonicalize(rest);
  };

  // What the quote signs: its message and signature, and the PCR values
  // checked against it (handle, keyId and hashAlg are labels), and the IMA
  // log's entries up to the quoted value (entries appended after the quote
  // are not used).  Base64 decoding skips characters outside the alphabet
  // and bits after the last full byte: the same bytes are the same quote.
  const bytes = value => (typeof value === 'string' ? Buffer.from(value, 'base64') : Buffer.alloc(0));
  const originalLog = bytes(setup.evidence.ima.log);
  const hardware = evidence => {
    const quote = evidence.tpm && evidence.tpm.quote;
    const log = evidence.ima && typeof evidence.ima === 'object' ? bytes(evidence.ima.log) : Buffer.alloc(0);
    return util.canonicalize({
      quote: quote && typeof quote === 'object'
        ? {message: bytes(quote.message).toString('hex'), signature: bytes(quote.signature).toString('hex'), pcrs: quote.pcrs ?? null}
        : quote ?? null,
      ima: log.subarray(0, originalLog.length).equals(originalLog),
    });
  };

  const rng = random(SEED + 2);
  const problems = [];
  const iterations = Math.ceil(ITERATIONS / 4);
  for (let index = 0; index < iterations; index++) {
    const {mutant, label} = makeMutant(setup.evidence, rng);
    let bound = false;
    try {
      bound = covered(mutant) !== covered(setup.evidence) || hardware(mutant) !== hardware(setup.evidence);
    } catch {
      bound = true;
    }

    try {
      const result = await withTimeout(setup.appraise(mutant), TIMEOUT);
      if (bound && result.status === 'pass') {
        problems.push(`#${index} ${label}: passed although the quote binds it: ${difference(setup.evidence, mutant).join('; ').slice(0, 300)}`);
      }
    } catch (error) {
      problems.push(`#${index} ${label}: threw ${error.message}`);
    }
  }

  assert.deepEqual(problems, []);
});

test('fuzzing the references: a registry or lockfile that disagrees with the server never passes', {skip: !linux, timeout: 10 * 60 * 1000}, async t => {
  const setup = await setupWorld(t);
  const {world, evidence, nonce} = setup;
  const rng = random(SEED + 1);
  const {alpha} = world.packages;
  const route = `/registry/alpha/-/alpha-${alpha.version}.tgz`;
  const original = world.upstream.routes[route];
  let cache = 0;
  const appraiseFresh = async candidate => {
    // A cold cache, so each case downloads its references again.
    const config = normalizeVerifierConfig({...world.verifierConfig, references: {...world.verifierConfig.references, cacheDir: path.join(world.root, `cache-${cache++}`)}});
    const references = new References({config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true});
    return withTimeout(appraiseServer({
      server: config.servers[0], evidence: candidate, nonce, references,
    }), TIMEOUT);
  };

  // The registry serves a different tarball for alpha.
  const tarballs = [
    () => {
      const body = Buffer.from(original.body);
      body[rng.int(body.length)] ^= 1 + rng.int(255);
      return {body};
    },
    () => ({body: original.body.subarray(0, rng.int(original.body.length))}),
    () => ({body: Buffer.alloc(0)}),
    () => ({status: 500, body: ''}),
    () => ({body: require('node:zlib').gzipSync(Buffer.alloc(1024 * 1024))}),
  ];
  for (const make of tarballs) {
    world.upstream.routes[route] = make();
    const result = await appraiseFresh(evidence);
    assert.notEqual(result.status, 'pass', JSON.stringify(world.upstream.routes[route]).slice(0, 80));
  }

  world.upstream.routes[route] = original;

  // The lockfile at a new commit pins other content; the server runs that commit.
  const lock = fs.readFileSync(path.join(world.repo, 'pnpm-lock.yaml'), 'utf8');
  const edits = [
    text => text.replace(alpha.integrity, `sha512-${Buffer.from(util.sha256('x') + util.sha256('y'), 'hex').toString('base64')}`),
    text => text.replace('alpha@1.0.0:', 'alpha@1.0.1:'),
    text => text.replace(`  alpha@1.0.0:\n    resolution: {integrity: ${alpha.integrity}}\n`, ''),
    text => text.replace(alpha.integrity, alpha.integrity.toUpperCase()),
  ];
  for (const [index, change] of edits.entries()) {
    const changed = change(lock);
    assert.notEqual(changed, lock);
    writeFiles(world.repo, {'pnpm-lock.yaml': changed});
    git(world.repo, 'commit', '-q', '-am', `lock ${index}`);
    const candidate = structuredClone(evidence);
    candidate.services[0].git.commit = git(world.repo, 'rev-parse', 'HEAD');
    candidate.services[0].files['pnpm-lock.yaml'][0] = sha256(changed);
    candidate.evidenceDigest = evidenceFormat.evidenceDigest(candidate);
    const result = await appraiseFresh(candidate);
    assert.notEqual(result.status, 'pass', `lockfile edit ${index}`);
  }
});

module.exports = {
  random, makeMutant, fuzz, setupWorld, NEUTRAL,
};
