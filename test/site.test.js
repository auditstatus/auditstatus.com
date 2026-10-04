const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const yaml = require('js-yaml');
const {schema: jsonSchema} = require('attestium');
const crypto = require('node:crypto');
const {build, slugify, configSchemas, structuredData} = require('../scripts/build-site.js');
const {normalizeAttesterConfig, normalizeVerifierConfig} = require('../lib/config');

const SITE = 'https://auditstatus.com';
const root = path.join(__dirname, '..');

// Schema.org types used in the structured data, with the properties each may carry.
const CREATIVE_WORK = ['@type', '@id', 'url', 'name', 'headline', 'description', 'inLanguage', 'isPartOf', 'publisher', 'author', 'image', 'dateModified', 'keywords', 'breadcrumb', 'mainEntity'];
const SCHEMA_ORG = {
  Organization: ['@type', '@id', 'name', 'url', 'logo', 'sameAs'],
  WebSite: ['@type', '@id', 'url', 'name', 'description', 'inLanguage', 'publisher'],
  WebPage: CREATIVE_WORK,
  TechArticle: CREATIVE_WORK,
  FAQPage: CREATIVE_WORK,
  Question: ['@type', 'name', 'acceptedAnswer'],
  Answer: ['@type', 'text'],
  BreadcrumbList: ['@type', '@id', 'itemListElement'],
  ListItem: ['@type', 'position', 'name', 'item'],
  Offer: ['@type', 'price', 'priceCurrency'],
  'SoftwareApplication,SoftwareSourceCode': ['@type', '@id', 'name', 'description', 'url', 'image', 'applicationCategory', 'operatingSystem', 'runtimePlatform', 'programmingLanguage', 'codeRepository', 'license', 'softwareVersion', 'downloadUrl', 'isAccessibleForFree', 'offers', 'publisher', 'author'],
};

function htmlFiles(dir) {
  return fs.readdirSync(dir, {withFileTypes: true}).flatMap(entry => {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return htmlFiles(file);
    }

    return entry.name.endsWith('.html') ? [file] : [];
  });
}

function targetFile(outDir, url) {
  const file = path.join(outDir, decodeURIComponent(url));
  return url.endsWith('/') ? path.join(file, 'index.html') : file;
}

function ids(html) {
  return new Set([...html.matchAll(/\sid="([^"]+)"/g)].map(m => m[1]));
}

function metaContent(html, attribute, name) {
  const match = new RegExp(`<meta ${attribute}="${name}" content="([^"]*)">`).exec(html);
  return match ? match[1] : null;
}

// Every node of the graph (and nested objects with a type) uses known types and properties.
function checkNode(node, where, problems) {
  if (Array.isArray(node)) {
    for (const item of node) {
      checkNode(item, where, problems);
    }

    return;
  }

  if (!node || typeof node !== 'object') {
    return;
  }

  if (node['@type']) {
    const type = [node['@type']].flat().join(',');
    const allowed = SCHEMA_ORG[type];
    if (allowed) {
      for (const key of Object.keys(node).filter(key => !allowed.includes(key))) {
        problems.push(`${where}: ${type} has unexpected property ${key}`);
      }
    } else {
      problems.push(`${where}: unexpected type ${type}`);
    }
  }

  for (const value of Object.values(node)) {
    checkNode(value, where, problems);
  }
}

test('slugs match GitHub heading ids', () => {
  assert.equal(slugify('1. Install the command line tool'), '1-install-the-command-line-tool');
  assert.equal(slugify('evidence, transport'), 'evidence-transport');
  assert.equal(slugify('Git deploys and PM2'), 'git-deploys-and-pm2');
  assert.equal(slugify('`report.json`'), 'reportjson');
});

test('site builds; links, metadata and structured data are complete', async t => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditstatus-site-'));
  t.after(() => fs.rmSync(outDir, {recursive: true, force: true}));
  const {pages} = await build({outDir});

  for (const url of ['/', '/docs/getting-started/', '/docs/registry/', '/docs/languages/node/', '/languages/node/', '/faq/', '/brand/', '/compare/', '/schema/', '/projects/']) {
    assert.ok(pages.includes(url), `${url} is not built`);
  }

  for (const file of ['404.html', 'sitemap.xml', 'robots.txt', 'llms.txt', 'llms-full.txt', 'manifest.webmanifest', 'style.css', 'site.js', 'favicon.svg', 'og.png', 'icon-512.png', 'brand/logo.svg', 'schema/attester.schema.json', 'schema/verifier.schema.json', 'schema/registry.schema.json', 'schema/report.schema.json', 'schema/report.example.json']) {
    assert.ok(fs.existsSync(path.join(outDir, file)), `${file} is missing`);
  }

  // GitHub Pages serves the site at its custom domain, from the root.
  assert.equal(fs.readFileSync(path.join(outDir, 'CNAME'), 'utf8').trim(), new URL(SITE).hostname);
  const webManifest = JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.webmanifest'), 'utf8'));
  assert.equal(webManifest.start_url, '/');
  assert.ok(webManifest.icons.every(icon => icon.src.startsWith('/') && fs.existsSync(path.join(outDir, icon.src))));

  const robots = fs.readFileSync(path.join(outDir, 'robots.txt'), 'utf8');
  assert.match(robots, new RegExp(`Sitemap: ${SITE}/sitemap.xml`));
  // Every crawler and AI agent may read every page.
  assert.match(robots, /^User-agent: \*\nAllow: \/$/m);
  assert.doesNotMatch(robots, /Disallow/);

  const sitemap = fs.readFileSync(path.join(outDir, 'sitemap.xml'), 'utf8');
  for (const url of pages) {
    assert.match(sitemap, new RegExp(`<loc>${SITE}${url}</loc><lastmod>\\d{4}-\\d\\d-\\d\\dT[\\d:]+(?:Z|[+-]\\d\\d:\\d\\d)</lastmod>`), `${url} is not in the sitemap`);
  }

  const llms = fs.readFileSync(path.join(outDir, 'llms.txt'), 'utf8');
  assert.match(llms, /^# Audit Status\n\n> .+\n/);
  const llmsLinks = [...llms.matchAll(/]\((https:\/\/[^)]*)\)/g)].map(match => match[1]).filter(url => url.startsWith(`${SITE}/`));
  assert.ok(llmsLinks.length > 10, 'llms.txt links to the pages');
  for (const url of llmsLinks) {
    assert.ok(fs.existsSync(path.join(outDir, url.slice(SITE.length))), `llms.txt links to missing ${url}`);
  }

  for (const file of ['attester', 'verifier', 'registry', 'report']) {
    const published = JSON.parse(fs.readFileSync(path.join(outDir, `schema/${file}.schema.json`), 'utf8'));
    assert.equal(published.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.equal(published.$id, `${SITE}/schema/${file}.schema.json`);
  }

  const cache = new Map();
  const read = file => {
    if (!cache.has(file)) {
      cache.set(file, fs.readFileSync(file, 'utf8'));
    }

    return cache.get(file);
  };

  const problems = [];
  const titles = new Map();
  const descriptions = new Map();
  for (const file of htmlFiles(outDir)) {
    const html = read(file);
    const page = path.relative(outDir, file);
    const title = /<title>([^<]+)<\/title>/.exec(html);
    const description = metaContent(html, 'name', 'description');
    assert.match(html, /<html lang="en">/, page);
    assert.ok(title, `${page} has no title`);
    assert.ok(description && description.length <= 160, `${page}: description missing or longer than 160 characters`);
    assert.equal((html.match(/<h1[\s>]/g) || []).length, 1, `${page} must have one h1`);
    assert.match(html, /<main id="main"/, page);
    for (const [name, value] of [['og:title', title[1]], ['og:description', description]]) {
      assert.equal(metaContent(html, 'property', name), value, `${page}: ${name}`);
    }

    assert.equal(metaContent(html, 'property', 'og:image'), `${SITE}/og.png`, page);
    assert.ok(html.includes(`<link rel="canonical" href="${SITE}/`), page);
    titles.set(title[1], [...(titles.get(title[1]) || []), page]);
    descriptions.set(description, [...(descriptions.get(description) || []), page]);

    const scripts = [...html.matchAll(/<script type="application\/ld\+json">([^<]+)<\/script>/g)];
    assert.equal(scripts.length, 1, `${page} needs one JSON-LD block`);
    const data = JSON.parse(scripts[0][1]);
    assert.equal(data['@context'], 'https://schema.org', page);
    checkNode(data['@graph'], page, problems);

    const alternate = /<link rel="alternate" type="text\/markdown" href="([^"]+)"/.exec(html);
    if (alternate) {
      alternate[1] = alternate[1].replace(SITE, '');
    }

    if (alternate && !fs.existsSync(path.join(outDir, alternate[1]))) {
      problems.push(`${page}: Markdown copy ${alternate[1]} is missing`);
    }

    assert.equal(new Set(ids(html)).size, [...html.matchAll(/\sid="([^"]+)"/g)].length, `${page} has duplicate ids`);
    for (const [img] of html.matchAll(/<img [^>]*>/g)) {
      assert.match(img, / alt="[^"]+"/, `${page}: image without alt`);
      assert.match(img, / width="\d+" height="\d+"/, `${page}: image without width and height`);
    }

    for (const [, raw] of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
      const href = raw.replaceAll('&amp;', '&');
      if (/^(?:https?:|mailto:)/.test(href)) {
        continue;
      }

      if (!href.startsWith('/') && !href.startsWith('#')) {
        problems.push(`${page}: relative link ${href}`);
        continue;
      }

      const [pathname, anchor] = href.split('#');
      const target = pathname ? targetFile(outDir, pathname.split('?')[0]) : file;
      if (!fs.existsSync(target)) {
        problems.push(`${page}: ${href} does not exist`);
        continue;
      }

      if (anchor && target.endsWith('.html') && !ids(read(target)).has(decodeURIComponent(anchor))) {
        problems.push(`${page}: ${href} has no matching id`);
      }
    }
  }

  for (const [value, where] of [...titles, ...descriptions]) {
    if (where.length > 1) {
      problems.push(`${where.join(', ')} share "${value}"`);
    }
  }

  assert.deepEqual(problems, []);
});

// A second validator, when one is installed (ajv comes with the lint tools).
function ajvValidator(schema) {
  const store = path.join(root, 'node_modules', '.pnpm');
  const candidates = fs.existsSync(store) ? fs.readdirSync(store).filter(name => /^ajv@8\./.test(name)) : [];
  for (const name of candidates) {
    try {
      const Ajv2020 = require(path.join(store, name, 'node_modules', 'ajv', 'dist', '2020.js')).default;
      const validate = new Ajv2020({strict: false, allErrors: true}).compile(schema);
      return value => ({valid: validate(value), errors: validate.errors || []});
    } catch {}
  }

  return null;
}

function validators(schema) {
  return [jsonSchema.compile(schema), ajvValidator(schema)].filter(Boolean);
}

function exampleConfigs(name) {
  const found = [];
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(file);
      } else if (entry.name === name) {
        found.push(file);
      }
    }
  };

  walk(path.join(root, 'examples'));
  return found;
}

test('configuration schemas accept every example and agree with lib/config.js', () => {
  const schemas = configSchemas();
  const attester = validators(schemas['attester.schema.json']);
  const verifier = validators(schemas['verifier.schema.json']);
  const load = file => yaml.load(fs.readFileSync(file, 'utf8'), {schema: yaml.JSON_SCHEMA});
  const attesterFiles = exampleConfigs('attester.yml');
  const verifierFiles = exampleConfigs('auditstatus.config.yml');
  assert.ok(attesterFiles.length > 1 && verifierFiles.length > 1);
  for (const [files, checks] of [[attesterFiles, attester], [verifierFiles, verifier]]) {
    for (const file of files) {
      for (const validate of checks) {
        const result = validate(load(file));
        assert.ok(result.valid, `${path.relative(root, file)}: ${JSON.stringify(result.errors)}`);
      }
    }
  }

  const base = load(path.join(root, 'examples', 'auditstatus.config.yml'));
  const server = base.servers[0];
  const invalid = [
    [attester, normalizeAttesterConfig, {version: 2, bogus: true}],
    [attester, normalizeAttesterConfig, {version: 2, tpm: {pcrs: [24]}}],
    [attester, normalizeAttesterConfig, {version: 2, services: [{name: 'app', ecosystems: ['cobol']}]}],
    [verifier, normalizeVerifierConfig, {...base, servers: [{name: 'web'}]}],
    [verifier, normalizeVerifierConfig, {...base, servers: [{...server, port: 70_000}]}],
    [verifier, normalizeVerifierConfig, {...base, servers: [{...server, tpm: {required: true}}]}],
    [verifier, normalizeVerifierConfig, {...base, servers: [{...server, transport: 'local'}]}],
    [verifier, normalizeVerifierConfig, {...base, build: {command: 'make', outputs: ['node_modules/x']}}],
    // Rules across settings.
    [verifier, normalizeVerifierConfig, {...base, servers: [{...server, tpm: {ima: true}}]}],
    [verifier, normalizeVerifierConfig, {...base, servers: [{...server, tpm: {required: true, publicKey: null}}]}],
    [verifier, normalizeVerifierConfig, {...base, servers: [{...server, host: null}]}],
    [verifier, normalizeVerifierConfig, {services: [{name: 'web'}], servers: [server]}],
    [verifier, normalizeVerifierConfig, {servers: [server]}],
    [attester, normalizeAttesterConfig, {version: 2}],
    [attester, normalizeAttesterConfig, {projectRoot: '/srv/app', services: [{name: 'app', root: '/srv/app'}]}],
    [attester, normalizeAttesterConfig, {processes: {uid: 1000}}],
    [attester, normalizeAttesterConfig, {services: [{name: 'app', root: '/srv/app', container: {name: 'app'}}]}],
    [attester, normalizeAttesterConfig, {services: [{name: 'app'}]}],
    [attester, normalizeAttesterConfig, {services: [{name: 'app', container: {}}]}],
    [attester, normalizeAttesterConfig, {services: [{name: 'app', container: {name: null}}]}],
  ];
  for (const [checks, normalize, config] of invalid) {
    assert.throws(() => normalize(structuredClone(config)), /Invalid configuration/, JSON.stringify(config));
    for (const validate of checks) {
      assert.equal(validate(config).valid, false, JSON.stringify(config));
    }
  }

  // A null setting is a missing one, to both.
  const valid = [
    [attester, normalizeAttesterConfig, {services: [{name: 'app', root: '/srv/app', container: null}], processes: null, exclude: null}],
    [attester, normalizeAttesterConfig, {projectRoot: '/srv/app', services: null}],
    [attester, normalizeAttesterConfig, {services: [{name: 'app', container: {name: null, image: 'ghcr.io/example/app'}}]}],
    [verifier, normalizeVerifierConfig, {...base, servers: [{...server, transport: null}]}],
    [verifier, normalizeVerifierConfig, {services: [{name: 'web', image: {repository: 'ghcr.io/example/app'}}], servers: [server]}],
  ];
  for (const [checks, normalize, config] of valid) {
    normalize(structuredClone(config));
    for (const validate of checks) {
      const result = validate(config);
      assert.ok(result.valid, `${JSON.stringify(config)}: ${JSON.stringify(result.errors)}`);
    }
  }
});

test('the registry schema accepts every registry file and example, and agrees with lib/registry.js', t => {
  const registry = require('../lib/registry');
  const checks = validators(configSchemas()['registry.schema.json']);
  const load = file => yaml.load(fs.readFileSync(file, 'utf8'), {schema: yaml.JSON_SCHEMA});
  const files = ['registry', 'examples/registry'].flatMap(dir => registry.listProjects(path.join(root, dir)).map(slug => path.join(root, dir, `${slug}.yml`)));
  assert.ok(files.length > 5);
  for (const file of files) {
    for (const validate of checks) {
      const result = validate(load(file));
      assert.ok(result.valid, `${path.relative(root, file)}: ${JSON.stringify(result.errors)}`);
    }
  }

  // What lib/registry.js refuses, the schema refuses.
  const base = load(path.join(root, 'examples', 'registry', 'minimal.yml'));
  const server = base.servers[0];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auditstatus-registry-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  for (const [label, file] of [
    ['no project', {...base, project: undefined}],
    ['a private host', {...base, servers: [{...server, host: '10.0.0.5'}]}],
    ['a host key that is not one', {...base, servers: [{...server, hostKeys: ['ssh-ed25519 AAAA']}]}],
    ['no servers', {...base, servers: []}],
    ['another transport', {...base, servers: [{...server, transport: 'local'}]}],
    ['a catch-all pattern', {...base, policy: {allowUntracked: ['**']}}],
    ['a reference', {...base, references: {registryUrl: 'https://npm.example.com'}}],
    ['a build account', {...base, build: {command: 'make', outputs: ['dist/**'], user: 'root'}}],
    ['a Node.js the verifier cannot run', {...base, setup: {node: '16'}}],
    ['a repository on another protocol', {...base, repository: {url: 'git://example.com/app.git'}}],
  ]) {
    for (const key of Object.keys(file)) {
      if (file[key] === undefined) {
        delete file[key];
      }
    }

    fs.writeFileSync(path.join(directory, 'bad.yml'), yaml.dump(file));
    assert.throws(() => registry.readProject('bad', directory), {name: 'ConfigError'}, label);
    for (const validate of checks) {
      assert.equal(validate(file).valid, false, label);
    }
  }
});

test('report.json matches the report schema', {skip: process.platform !== 'linux'}, async t => {
  const reportSchema = JSON.parse(fs.readFileSync(path.join(root, 'site', 'schema', 'report.schema.json'), 'utf8'));
  const checks = validators(reportSchema);
  const example = JSON.parse(fs.readFileSync(path.join(root, 'site', 'schema', 'report.example.json'), 'utf8'));
  const {createWorld} = require('./world');
  const {verify} = require('../lib/verify');
  const world = await createWorld(t);
  const report = await verify(normalizeVerifierConfig(world.verifierConfig), {httpOptions: {retryDelay: 1}});
  // A failing one, with details that are texts (a process finding) and lists
  // (a changed package).
  await world.startApp({env: {PATH: process.env.PATH, NODE_PATH: '/opt/elsewhere'}});
  fs.writeFileSync(path.join(world.deployDir, 'node_modules', 'alpha', 'index.js'), 'module.exports = "changed";\n');
  const failing = await verify(normalizeVerifierConfig(world.verifierConfig), {httpOptions: {retryDelay: 1}});
  assert.equal(failing.status, 'fail');
  const details = failing.servers[0].findings.map(finding => finding.detail);
  assert.ok(details.some(detail => typeof detail === 'string') && details.some(detail => Array.isArray(detail)), JSON.stringify(failing.servers[0].findings));
  for (const value of [example, report, failing]) {
    for (const validate of checks) {
      const result = validate(value);
      assert.ok(result.valid, JSON.stringify(result.errors));
    }
  }

  assert.equal(validators(reportSchema)[0]({...report, status: 'passing'}).valid, false);
});

test('structured data cannot end its script element', () => {
  const title = '</script><script>alert(1)</script><!--';
  const json = structuredData({
    kind: 'doc', url: '/x/', title, description: 'line\u2028separator', lastmod: '2026-01-01T00:00:00Z',
  });
  assert.ok(!json.includes('<'), json);
  assert.ok(!json.includes('\u2028'));
  assert.ok(JSON.parse(json)['@graph'].some(node => node.name === title));
});

test('every page has a Content-Security-Policy that allows what it loads, and no inline script but the theme', async t => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'site-csp-'));
  t.after(() => fs.rmSync(outDir, {recursive: true, force: true}));
  await build({outDir});
  const files = htmlFiles(outDir);
  assert.ok(files.length > 5);
  for (const file of files) {
    const where = path.relative(outDir, file);
    const html = fs.readFileSync(file, 'utf8');
    const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
    assert.ok(meta, `${where}: no Content-Security-Policy`);
    // Before anything it governs.
    assert.ok(meta.index < html.indexOf('<script') && meta.index < html.indexOf('<link'), `${where}: the policy comes too late`);
    const policy = new Map(meta[1].replaceAll('&amp;', '&').split(';').map(directive => directive.trim().split(/\s+/)).map(([name, ...values]) => [name, values]));
    assert.deepEqual(policy.get('default-src'), ['\'none\'']);
    assert.deepEqual(policy.get('base-uri'), ['\'none\'']);
    assert.deepEqual(policy.get('form-action'), ['\'none\'']);
    const scriptSources = policy.get('script-src');
    assert.ok(!scriptSources.some(source => /unsafe|\*|https?:/.test(source)), `${where}: ${scriptSources.join(' ')}`);
    const allows = (directive, url) => {
      if (url.startsWith('/') && !url.startsWith('//')) {
        return policy.get(directive).includes('\'self\'');
      }

      const {origin} = new URL(url);
      return policy.get(directive).includes(origin);
    };

    // Every inline script runs by its hash; data blocks do not run.
    for (const [, attributes, body] of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
      const src = /\ssrc="([^"]+)"/.exec(attributes);
      if (src) {
        assert.ok(allows('script-src', src[1]), `${where}: script ${src[1]} is not allowed`);
      } else if (!/type="application\/ld\+json"/.test(attributes)) {
        const hash = `'sha256-${crypto.createHash('sha256').update(body).digest('base64')}'`;
        assert.ok(scriptSources.includes(hash), `${where}: inline script ${body.slice(0, 40)} is not allowed`);
      }
    }

    assert.doesNotMatch(html, /<[a-z][^>]*\son[a-z]+=/i, `${where}: inline event handler`);
    assert.doesNotMatch(html, /\s(?:href|src)="\s*javascript:/i, `${where}: javascript: URL`);
    for (const [, href] of html.matchAll(/<link rel="stylesheet" href="([^"]+)"/g)) {
      assert.ok(allows('style-src', href), `${where}: stylesheet ${href} is not allowed`);
    }

    for (const [, href] of html.matchAll(/<link rel="preload" href="([^"]+)" as="font"/g)) {
      assert.ok(allows('font-src', href), `${where}: font ${href} is not allowed`);
    }

    for (const [, src] of html.matchAll(/<img[^>]*\ssrc="([^"]+)"/g)) {
      assert.ok(allows('img-src', /^https?:/.test(src) ? src : '/'), `${where}: image ${src} is not allowed`);
    }
  }
});
