#!/usr/bin/env node
'use strict';

// Builds auditstatus.com into _site/: a hand-written landing page, one page per
// document in docs/, guides from site/pages/, a page per language, a brand
// page, JSON Schemas for the configuration files and the report, and
// the files search engines and agents read (sitemap.xml, robots.txt,
// llms.txt, a Markdown copy of every document). Plain HTML, one CSS file
// (site/style.css) and one small script (site/site.js); no framework.

const {execFileSync} = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {createRequire} = require('node:module');

// Marked is ESM-only: loaded with import() in build(), which works on Node 18 too.
let Marked;

const root = path.resolve(__dirname, '..');
const siteDir = path.join(root, 'site');

const SITE = {
  name: 'Audit Status',
  url: 'https://auditstatus.com',
  repo: 'https://github.com/auditstatus/auditstatus.com',
  branch: 'main',
  tagline: 'Verify what your servers run',
  description: 'Audit Status verifies that production servers run exactly the code in a public repository, and publishes a report and a badge.',
  keywords: 'remote attestation, production verification, open source transparency, supply chain security, TPM, status page, CI',
  locale: 'en_US',
  themeLight: '#fbf7ef',
  themeDark: '#0e1b1b',
  imageAlt: 'Audit Status: verify that production runs the public code',
  fonts: 'https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@500;600&display=swap',
  // The Latin subset of IBM Plex Sans that the stylesheet above serves: headings and the wordmark.
  fontPreload: 'https://fonts.gstatic.com/s/ibmplexsans/v23/zYXzKVElMYYaJe8bpLHnCwDKr932-G7dytD-Dmu1syxeKYY.woff2',
};

const PUBLISHER = {
  '@type': 'Organization',
  '@id': 'https://forwardemail.net/#organization',
  name: 'Forward Email',
  url: 'https://forwardemail.net',
  logo: 'https://forwardemail.net/img/logo-square.svg',
  sameAs: ['https://github.com/forwardemail'],
};

// Guides in site/pages/, in this order; faq.md is the FAQ page.
const GUIDES = ['verify-production-matches-source', 'open-source-transparency', 'kubernetes-attestation', 'runtime-integrity-monitoring', 'compare'];

const NAV = [
  {group: 'Start', pages: [['docs/README.md', 'Overview'], ['docs/registry.md', 'Public registry'], ['docs/getting-started.md'], ['docs/how-it-works.md']]},
  {group: 'Set up', pages: [['docs/attester.md'], ['docs/verifier.md'], ['docs/configuration.md'], ['docs/containers.md'], ['docs/kubernetes.md'], ['docs/hardware.md'], ['docs/monitor.md']]},
  {
    group: 'Languages',
    pages: [['docs/languages/README.md', 'All languages'], ['docs/languages/node.md'], ['docs/languages/python.md'], ['docs/languages/ruby.md'], ['docs/languages/elixir.md'], ['docs/languages/php.md'], ['docs/languages/java.md'], ['docs/languages/dotnet.md'], ['docs/languages/go.md'], ['docs/languages/rust.md'], ['docs/languages/binaries.md', 'Releases and binaries']],
  },
  {group: 'Reference', pages: [['docs/reports.md'], ['docs/threat-model.md'], ['docs/adopters.md']]},
];

// Glossary: the first use of each term on a docs page gets a tooltip.
// [pattern, definition, regular expression flags]
const GLOSSARY = [
  ['relying party', 'Whoever reads the verifier\'s result: the report, the badge or a status page.', 'i'],
  ['attester', 'The program on each server. It collects facts and reports them as evidence; it never decides whether the server passes.', 'i'],
  ['verifier', 'The program in CI that sends a nonce, fetches references itself, compares, and writes the report.', 'i'],
  ['nonce', 'A random value the verifier chooses for one run, so that an old answer cannot be replayed.', 'i'],
  ['forced command', 'An SSH authorized_keys option that runs one fixed command whatever the client asks for. The verifier\'s key can only run the attester.', 'i'],
  ['RATS', 'Remote ATtestation procedureS: the IETF architecture (RFC 9334) that defines attester, verifier and relying party.'],
  ['TPM', 'Trusted Platform Module: a chip with keys that cannot be exported and registers (PCRs) that can be extended but never set.'],
  ['PCRs?', 'Platform Configuration Register: a TPM register that can only be extended with a hash. Firmware, bootloader and kernel extend PCRs with what they load.'],
  ['IMA', 'Integrity Measurement Architecture: the Linux kernel hashes files as they are used, logs each hash and extends PCR 10.'],
  ['EK', 'Endorsement key: the TPM\'s identity key, certified by its manufacturer.'],
  ['AK', 'Attestation key: a key held by the TPM that signs quotes. The verifier pins it at enrollment.'],
  ['SEV-SNP', 'AMD Secure Encrypted Virtualization with Secure Nested Paging: confidential VMs whose launch measurement the AMD chip signs.'],
  ['TDX', 'Intel Trust Domain Extensions: confidential VMs whose measurement is signed through Intel\'s quoting enclave.'],
  ['VCEK', 'Versioned Chip Endorsement Key: the AMD per-chip key that signs SEV-SNP reports, certified through the ASK to AMD\'s root.'],
  ['DSSE', 'Dead Simple Signing Envelope: signs a payload together with its type. Used by in-toto and Sigstore attestations.'],
  ['Sigstore', 'A public signing service: short-lived certificates from Fulcio tied to an OIDC identity, with signatures logged in Rekor.'],
  ['Rekor', 'Sigstore\'s public, append-only transparency log of signatures.'],
  ['Fulcio', 'Sigstore\'s certificate authority. It issues short-lived signing certificates for OIDC identities.'],
  ['TUF', 'The Update Framework: signed, versioned metadata for distributing keys and files. Sigstore ships its trusted root with it.'],
  ['OCI', 'Open Container Initiative: the standard image and registry formats. Manifests and layers are addressed by SHA-256 digest.'],
  ['SBOM', 'Software bill of materials: a list of the components in a piece of software.'],
];

const LANGS = {
  js: 'JavaScript', javascript: 'JavaScript', ts: 'TypeScript', json: 'JSON', sh: 'Shell', bash: 'Shell', shell: 'Shell', console: 'Shell', python: 'Python', py: 'Python', yaml: 'YAML', yml: 'YAML', text: 'Text', txt: 'Text',
};

// ---------------------------------------------------------------------------
// Helpers

function esc(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

// JSON inside a <script> element: "<" is written \u003c (as are U+2028 and
// U+2029), so no value can end the element or open a comment.
function jsonForScript(value) {
  return JSON.stringify(value).replaceAll('<', String.raw`\u003c`).replaceAll('\u2028', String.raw`\u2028`).replaceAll('\u2029', String.raw`\u2029`);
}

// The only inline script: applies the saved theme before the first paint.
const THEME_SCRIPT = 'try{var t=localStorage.getItem(\'theme\');if(t===\'light\'||t===\'dark\')document.documentElement.dataset.theme=t}catch(e){}';

// Content-Security-Policy: scripts from this site and the theme script (by
// hash), styles and fonts from this site and Google Fonts.  Inline style
// attributes stay allowed (colour swatches, table alignment).
function contentSecurityPolicy() {
  const hash = crypto.createHash('sha256').update(THEME_SCRIPT).digest('base64');
  return [
    'default-src \'none\'',
    `script-src 'self' 'sha256-${hash}'`,
    'style-src \'self\' \'unsafe-inline\' https://fonts.googleapis.com',
    'font-src https://fonts.gstatic.com',
    'img-src \'self\' https://forwardemail.net https://img.shields.io',
    'manifest-src \'self\'',
    'base-uri \'none\'',
    'form-action \'none\'',
    'upgrade-insecure-requests',
  ].join('; ');
}

function stripTags(html) {
  return html.replaceAll(/<[^>]*>/g, '')
    .replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&#39;', '\'').replaceAll('&amp;', '&');
}

// GitHub's heading id algorithm (github-slugger), so existing anchors keep working.
function slugify(text) {
  return text.toLowerCase().trim().replaceAll(/[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu, '').replaceAll(' ', '-');
}

function createSlugger() {
  const occurrences = new Map();
  return text => {
    const original = slugify(text);
    let slug = original;
    while (occurrences.has(slug)) {
      occurrences.set(original, occurrences.get(original) + 1);
      slug = `${original}-${occurrences.get(original)}`;
    }

    occurrences.set(slug, 0);
    return slug;
  };
}

function hash(content) {
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 10);
}

function plain(markdown) {
  return markdown.replaceAll(/`([^`]*)`/g, '$1').replaceAll(/\[([^\]]*)]\([^)]*\)/g, '$1').replaceAll(/[*_]/g, '').replaceAll(/\s+/g, ' ').trim();
}

function truncate(text, max) {
  if (text.length <= max) {
    return text;
  }

  const cut = text.slice(0, max);
  return `${cut.slice(0, cut.lastIndexOf(' ')).replace(/[,;:.]$/, '')}…`;
}

// ---------------------------------------------------------------------------
// Syntax highlighting: comments, strings, keywords and numbers. Nothing more.

const KEYWORDS = {
  js: 'async|await|break|case|catch|class|const|continue|default|delete|else|export|extends|false|finally|for|function|if|import|in|instanceof|let|new|null|of|return|static|switch|this|throw|true|try|typeof|undefined|var|while',
  python: 'and|as|assert|async|await|break|class|continue|def|elif|else|except|False|finally|for|from|if|import|in|is|lambda|None|not|or|pass|raise|return|True|try|while|with|yield',
  json: 'true|false|null',
  sh: 'if|then|else|fi|for|do|done|case|esac|export|sudo',
  yaml: 'true|false|null',
};

const COMMENTS = {
  js: String.raw`\/\/[^\n]*|\/\*[\s\S]*?\*\/`, python: String.raw`#[^\n]*`, json: '(?!)', sh: String.raw`(?<=^|\s)#[^\n]*`, yaml: String.raw`(?<=^|\s)#[^\n]*`,
};

const LEXERS = {};
for (const [lang, words] of Object.entries(KEYWORDS)) {
  const string = lang === 'js'
    ? String.raw`'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|\x60(?:\\.|[^\x60\\])*\x60`
    : String.raw`'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"`;
  const key = lang === 'yaml' ? String.raw`|(?<p>^[ \t-]*[\w.-]+(?=:))` : '';
  LEXERS[lang] = new RegExp(String.raw`(?<c>${COMMENTS[lang]})|(?<s>${string})|(?<k>\b(?:${words})\b)|(?<n>\b\d[\d_.]*\b)${key}`, 'gm');
}

Object.assign(LEXERS, {
  javascript: LEXERS.js, ts: LEXERS.js, py: LEXERS.python, bash: LEXERS.sh, shell: LEXERS.sh, yml: LEXERS.yaml,
});

function highlight(code, lang) {
  const lexer = LEXERS[lang];
  if (!lexer) {
    return esc(code);
  }

  let out = '';
  let last = 0;
  for (const match of code.matchAll(lexer)) {
    if (match[0] === '') {
      continue;
    }

    const kind = Object.keys(match.groups).find(name => match.groups[name] !== undefined);
    out += esc(code.slice(last, match.index)) + `<span class="t-${kind}">${esc(match[0])}</span>`;
    last = match.index + match[0].length;
  }

  return out + esc(code.slice(last));
}

function codeBlock(code, lang, label) {
  const name = label || LANGS[lang] || (lang ? lang.toUpperCase() : 'Text');
  return `<div class="code"><div class="code-bar"><span>${esc(name)}</span><button class="copy" type="button">Copy</button></div>`
    + `<pre><code${lang ? ` class="language-${esc(lang)}"` : ''}>${highlight(code.replace(/\n$/, ''), lang)}</code></pre></div>\n`;
}

// ---------------------------------------------------------------------------
// Pages and links

function listDocs() {
  const files = [];
  const walk = dir => {
    const entries = fs.readdirSync(path.join(root, dir), {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const rel = `${dir}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(rel);
      } else if (entry.name.endsWith('.md')) {
        files.push(rel);
      }
    }
  };

  walk('docs');
  return files;
}

function urlFor(source) {
  if (source === 'README.md') {
    return '/';
  }

  if (source === 'SPEC.md') {
    return '/spec/';
  }

  return `/${source.replace(/(^|\/)README\.md$/, '$1').replace(/\.md$/, '/')}`;
}

// Repository files published on the site as they are: path in repo -> URL.
const PUBLISHED = {};

function rewriteLink(href, source, pages) {
  if (!href || href.startsWith('#') || href.startsWith('/') || /^[a-z][a-z\d+.-]*:/i.test(href)) {
    return href;
  }

  const [target, anchor] = href.split('#');
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(source), target)).replace(/^\.\//, '');
  const suffix = anchor === undefined ? '' : `#${anchor}`;
  if (pages.has(resolved)) {
    return urlFor(resolved) + suffix;
  }

  if (PUBLISHED[resolved]) {
    return PUBLISHED[resolved] + suffix;
  }

  const full = path.join(root, resolved);
  const kind = fs.existsSync(full) && fs.statSync(full).isDirectory() ? 'tree' : 'blob';
  return `${SITE.repo}/${kind}/${SITE.branch}/${resolved.replace(/\/$/, '')}${suffix}`;
}

// ---------------------------------------------------------------------------
// Markdown

function renderMarkdown(markdown, source, pages) {
  const slug = createSlugger();
  const toc = [];
  const marked = new Marked({gfm: true});
  marked.use({
    renderer: {
      heading({tokens, depth}) {
        const inner = this.parser.parseInline(tokens);
        const id = slug(stripTags(inner));
        if (depth === 2 || depth === 3) {
          toc.push({id, depth, html: inner.replaceAll(/<\/?a[^>]*>/g, '')});
        }

        return `<h${depth} id="${id}">${inner}<a class="h-anchor" href="#${id}" aria-label="Link to this section">#</a></h${depth}>\n`;
      },
      link({href, title, tokens}) {
        const url = rewriteLink(href, source, pages);
        const external = /^https?:/.test(url) && !url.startsWith(SITE.url);
        return `<a href="${esc(url)}"${title ? ` title="${esc(title)}"` : ''}${external ? ' rel="noopener"' : ''}>${this.parser.parseInline(tokens)}</a>`;
      },
      image({href, text}) {
        return `<img src="${esc(rewriteLink(href, source, pages))}" alt="${esc(text)}" loading="lazy">`;
      },
      code({text, lang}) {
        return codeBlock(text, (lang || '').split(/\s/)[0].toLowerCase());
      },
      table(token) {
        const cell = (c, tag) => `<${tag}${c.align ? ` style="text-align:${c.align}"` : ''}>${this.parser.parseInline(c.tokens)}</${tag}>`;
        const head = token.header.map(c => cell(c, 'th')).join('');
        const rows = token.rows.map(row => `<tr>${row.map(c => cell(c, 'td')).join('')}</tr>`).join('\n');
        const headless = token.header.every(c => c.text.trim() === '');
        return `<div class="table-wrap"><table${headless ? ' class="no-head"' : ''}>${headless ? '' : `<thead><tr>${head}</tr></thead>`}<tbody>${rows}</tbody></table></div>\n`;
      },
    },
  });
  return {html: marked.parse(markdown), toc};
}

// Wrap the first use of each glossary term in a tooltip, outside code, links,
// headings and buttons.
function addGlossary(html, prefix) {
  const skip = new Set(['a', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'button', 'script', 'style', 'svg', 'th']);
  const remaining = new Map(GLOSSARY.map(([term, text, flags]) => [term, {text, pattern: new RegExp(String.raw`(?<![\w-])${term}(?![\w-])`, flags || '')}]));
  let depth = 0;
  let count = 0;
  return html.split(/(<[^>]+>)/).map(part => {
    if (part.startsWith('<')) {
      const match = /^<(\/?)([a-z\d]+)/i.exec(part);
      if (match && skip.has(match[2].toLowerCase())) {
        depth += match[1] ? -1 : 1;
      }

      return part;
    }

    if (depth > 0 || remaining.size === 0 || part.trim() === '') {
      return part;
    }

    const found = [];
    for (const [term, {text: definition, pattern}] of remaining) {
      const m = pattern.exec(part);
      if (!m || found.some(f => m.index < f.end && m.index + m[0].length > f.start)) {
        continue;
      }

      found.push({
        start: m.index, end: m.index + m[0].length, definition, word: m[0],
      });
      remaining.delete(term);
    }

    let text = part;
    for (const f of found.sort((a, b) => b.start - a.start)) {
      const id = `${prefix}-${++count}`;
      text = `${text.slice(0, f.start)}<span class="term" tabindex="0" aria-describedby="${id}">${f.word}<span class="tip" role="tooltip" id="${id}">${esc(f.definition)}</span></span>${text.slice(f.end)}`;
    }

    return text;
  }).join('');
}

// ---------------------------------------------------------------------------
// Templates

// A brand SVG from site/brand/, for use inside a page: its own title and
// styles removed (site/style.css styles the as-* classes), hidden from
// assistive technology because a text label always sits next to it.
function svgInline(file, className) {
  return fs.readFileSync(path.join(siteDir, 'brand', file), 'utf8')
    .replace(/<title[^>]*>[^<]*<\/title>/, '')
    .replace(/<style>[^<]*<\/style>/, '')
    .replace(' role="img" aria-labelledby="t"', '')
    .replace('<svg ', `<svg class="${className}" aria-hidden="true" focusable="false" `)
    .replaceAll(/\n\s*/g, '')
    .trim();
}

const ICONS = {
  theme: '<svg class="i-system" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 3.5a6.5 6.5 0 0 1 0 13z" fill="currentColor"/></svg>'
    + '<svg class="i-light" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="3.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 1.5v2.5M10 16v2.5M1.5 10H4M16 10h2.5M4 4l1.8 1.8M14.2 14.2 16 16M4 16l1.8-1.8M14.2 5.8 16 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
    + '<svg class="i-dark" viewBox="0 0 20 20" aria-hidden="true"><path d="M16.5 12.2A7 7 0 0 1 7.8 3.5a7 7 0 1 0 8.7 8.7z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  menu: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 6h14M3 10h14M3 14h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
  github: '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>',
};

const CHECK = '<svg class="check" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="m3.5 8.5 3 3 6-7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function brandLink() {
  return `<a class="brand" href="/">${svgInline('favicon.svg', 'mark')}<span>${SITE.name}</span></a>`;
}

// Structured data: the publisher and the site on every page, plus what the page is.
function structuredData(p) {
  const url = SITE.url + p.url;
  const image = `${SITE.url}/og.png`;
  const website = {
    '@type': 'WebSite',
    '@id': `${SITE.url}/#website`,
    url: `${SITE.url}/`,
    name: SITE.name,
    description: SITE.description,
    inLanguage: 'en',
    publisher: {'@id': PUBLISHER['@id']},
  };
  const graph = [PUBLISHER, website];
  const crumbs = p.crumbs
    ? {
      '@type': 'BreadcrumbList',
      '@id': `${url}#breadcrumbs`,
      itemListElement: p.crumbs.map((crumb, index) => ({
        '@type': 'ListItem', position: index + 1, name: crumb.name, item: SITE.url + crumb.url,
      })),
    }
    : null;
  const article = type => ({
    '@type': type,
    '@id': `${url}#main`,
    url,
    name: p.title,
    headline: p.heading || p.title,
    description: p.description,
    inLanguage: 'en',
    isPartOf: {'@id': website['@id']},
    publisher: {'@id': PUBLISHER['@id']},
    author: {'@id': PUBLISHER['@id']},
    image,
    dateModified: p.lastmod,
    ...(p.keywords ? {keywords: p.keywords} : {}),
    ...(crumbs ? {breadcrumb: {'@id': crumbs['@id']}} : {}),
  });

  switch (p.kind) {
    case 'home': {
      const {version} = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      graph.push({
        '@type': ['SoftwareApplication', 'SoftwareSourceCode'],
        '@id': `${SITE.url}/#software`,
        name: SITE.name,
        description: SITE.description,
        url: `${SITE.url}/`,
        image,
        applicationCategory: 'DeveloperApplication',
        operatingSystem: 'Linux',
        runtimePlatform: 'Node.js 18 or later, or the single-file release binary',
        programmingLanguage: 'JavaScript',
        codeRepository: SITE.repo,
        license: 'https://opensource.org/licenses/MIT',
        softwareVersion: version,
        downloadUrl: `${SITE.repo}/releases`,
        isAccessibleForFree: true,
        offers: {'@type': 'Offer', price: '0', priceCurrency: 'USD'},
        publisher: {'@id': PUBLISHER['@id']},
        author: {'@id': PUBLISHER['@id']},
      });

      break;
    }

    case 'doc':
    case 'guide':
    case 'language': {
      graph.push(article('TechArticle'));

      break;
    }

    case 'faq': {
      graph.push({
        ...article('FAQPage'),
        mainEntity: p.faq.map(item => ({
          '@type': 'Question', name: item.question, acceptedAnswer: {'@type': 'Answer', text: item.answer},
        })),
      });

      break;
    }

    default: {
      graph.push(article('WebPage'));
    }
  }

  if (crumbs) {
    graph.push(crumbs);
  }

  return jsonForScript({'@context': 'https://schema.org', '@graph': graph});
}

function head(p, assets) {
  const url = SITE.url + p.url;
  const image = `${SITE.url}/og.png`;
  const meta = (name, content) => `<meta name="${name}" content="${esc(content)}">`;
  const property = (name, content) => `<meta property="${name}" content="${esc(content)}">`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${esc(contentSecurityPolicy())}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.title)}</title>
${meta('description', p.description)}
${p.keywords ? meta('keywords', p.keywords) : ''}
${p.kind === 'error' ? meta('robots', 'noindex') : ''}
<link rel="canonical" href="${url}">
${p.markdown ? `<link rel="alternate" type="text/markdown" href="${url}index.md" title="Markdown">` : ''}
${property('og:type', p.kind === 'home' ? 'website' : 'article')}
${property('og:site_name', SITE.name)}
${property('og:locale', SITE.locale)}
${property('og:title', p.title)}
${property('og:description', p.description)}
${property('og:url', url)}
${property('og:image', image)}
${property('og:image:width', '1200')}
${property('og:image:height', '630')}
${property('og:image:alt', SITE.imageAlt)}
${meta('twitter:card', 'summary_large_image')}
${meta('twitter:title', p.title)}
${meta('twitter:description', p.description)}
${meta('twitter:image', image)}
${meta('twitter:image:alt', SITE.imageAlt)}
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="${SITE.themeLight}" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="${SITE.themeDark}" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<script>${THEME_SCRIPT}</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="preload" href="${SITE.fontPreload}" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${SITE.fonts}">
<link rel="stylesheet" href="/style.css?v=${assets.css}">
<script src="/site.js?v=${assets.js}" defer></script>
<script type="application/ld+json">${structuredData(p)}</script>
</head>`.replaceAll(/\n{2,}/g, '\n');
}

function header(active) {
  const link = (href, label, key) => `<li><a href="${href}"${active === key ? ' aria-current="page"' : ''}>${label}</a></li>`;
  return `<a class="skip" href="#main">Skip to content</a>
<header class="site-header">
<div class="wrap header-row">
${brandLink()}
<nav class="site-nav" id="site-nav" aria-label="Main">
<ul>
${link('/docs/', 'Docs', 'docs')}
${link('/docs/languages/', 'Languages', 'languages')}
${link('/docs/reports/', 'Reports', 'reports')}
<li><a href="${SITE.repo}" rel="noopener">${ICONS.github}<span>GitHub</span></a></li>
</ul>
</nav>
<div class="header-actions">
<button class="icon-button theme-toggle" type="button" aria-label="Theme: system" title="Theme: system">${ICONS.theme}</button>
<button class="icon-button menu-toggle" type="button" aria-expanded="false" aria-controls="site-nav" aria-label="Menu">${ICONS.menu}</button>
</div>
</div>
</header>`;
}

function footer(guides) {
  const list = (id, title, links) => `<nav aria-labelledby="${id}"><h2 id="${id}">${title}</h2><ul>${links.map(([href, label]) => `<li><a href="${href}"${href.startsWith('http') ? ' rel="noopener"' : ''}>${label}</a></li>`).join('')}</ul></nav>`;
  return `<footer class="site-footer">
<div class="wrap footer-grid">
<div class="footer-brand">
${brandLink()}
<p>Remote attestation of what your servers run. <a href="${SITE.repo}/blob/${SITE.branch}/LICENSE" rel="noopener">MIT license</a>.</p>
</div>
${list('f-docs', 'Documentation', [['/docs/getting-started/', 'Getting started'], ['/docs/how-it-works/', 'How it works'], ['/docs/configuration/', 'Configuration'], ['/docs/threat-model/', 'Threat model'], ['/faq/', 'FAQ']])}
${list('f-guides', 'Use cases', guides.filter(g => g.url !== '/compare/').map(g => [g.url, g.label]))}
${list('f-compare', 'Compare', [['/compare/#keylime', 'Keylime'], ['/compare/#system-transparency', 'System Transparency'], ['/compare/#slsa-provenance', 'SLSA provenance'], ['/compare/#sigstore', 'Sigstore']])}
${list('f-project', 'Project', [[SITE.repo, 'GitHub'], [`${SITE.repo}/releases`, 'Releases'], ['/projects/', 'Verified projects'], ['/schema/', 'JSON Schemas'], ['/brand/', 'Brand'], ['https://forwardemail.net/security', 'Security']])}
${list('f-related', 'Related', [['https://attestium.com', 'Attestium'], ['https://forwardemail.net', 'Forward Email'], ['https://status.forwardemail.net', 'Forward Email status']])}
</div>
</footer>`;
}

function render(p, context) {
  return `${head(p, context.assets)}
<body class="page-${p.kind}">
${header(p.active)}
${p.body}
${footer(context.guides)}
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// JSON Schemas for the configuration files and the report

// lib/config.js validates with its own small schema tables. They are data
// (type, required, extra) except a few hand-written checks, so they convert
// to JSON Schema 2020-12. The tables are module-private: evaluate the module
// source with one extra export line instead of changing the module.
function configTables() {
  const file = path.join(root, 'lib', 'config.js');
  const source = fs.readFileSync(file, 'utf8');
  const wrapped = `(function (exports, require, module, __filename, __dirname) {${source}\nmodule.exports.schemaTables = {ATTESTER_SCHEMA, VERIFIER_SCHEMA, SERVER_SCHEMA, ALLOWED_ATTESTER_SCHEMA, IMAGE_REPOSITORY, ECOSYSTEMS};\n})`;
  const module_ = {exports: {}};
  // A name of its own, so coverage tools do not take this copy, with its
  // wrapper, for the module itself.
  vm.runInThisContext(wrapped, {filename: `${file} (schema tables)`})(module_.exports, createRequire(file), module_, file, path.dirname(file));
  return module_.exports.schemaTables;
}

const URL_SOURCE = String.raw`^(?:https:\/\/|http:\/\/(?:127\.0\.0\.1|localhost)[:/])`;
const ENV_SOURCE = String.raw`^[A-Za-z_]\w{0,127}$`;
const PCR_BANK_NAMES = ['sha1', 'sha256', 'sha384', 'sha512'];

// JSON Schema for each hand-written check, by setting name. A new custom
// check in lib/config.js fails the build until it is described here.
function customSchema(key, tables) {
  const ports = {type: 'array', items: {type: 'integer', minimum: 1, maximum: 65_535}};
  const map = {
    ecosystems: {
      description: 'auto, false, or a list of ecosystems to check',
      anyOf: [{const: 'auto'}, {const: false}, {type: 'array', items: {enum: tables.ECOSYSTEMS}}],
    },
    inspectorPorts: ports,
    debugPorts: ports,
    outputs: {
      description: 'Patterns of files the build produces; never under node_modules',
      type: 'array',
      minItems: 1,
      items: {type: 'string', minLength: 1, pattern: String.raw`^(?!(?:\.\/)?node_modules(?:\/|$))`},
    },
    env: {type: 'object', propertyNames: {pattern: ENV_SOURCE}, additionalProperties: {type: 'string'}},
    passEnv: {type: 'array', items: {type: 'string', pattern: ENV_SOURCE}},
    identity: {
      description: 'Certificate claims to require; a value written /.../ is a regular expression',
      type: 'object',
      additionalProperties: {type: 'string'},
    },
    lockfiles: {
      description: 'Lockfile paths in the repository, by ecosystem',
      type: 'object',
      propertyNames: {enum: [...tables.ECOSYSTEMS, 'cargo']},
      additionalProperties: {type: 'string', pattern: String.raw`^(?!.*\.\.)`},
    },
    expectedPcrs: {
      description: 'Expected PCR values: bank, then PCR index, then hex value',
      type: 'object',
      propertyNames: {enum: PCR_BANK_NAMES},
      additionalProperties: {
        type: 'object',
        propertyNames: {pattern: String.raw`^\d{1,2}$`},
        additionalProperties: {type: 'string', pattern: String.raw`^(?:0x)?[\da-fA-F]+$`},
      },
    },
    registries: {
      description: 'Registry base URLs, for example a mirror',
      type: 'object',
      propertyNames: {enum: ['pypi', 'rubygems', 'hex', 'nuget', 'maven', 'packagist', 'uvSource', 'goproxy', 'crates']},
      additionalProperties: {type: 'string', pattern: URL_SOURCE},
    },
    containerRegistries: {
      description: 'Container registries by name: {url, tokenEnv}',
      type: 'object',
      additionalProperties: {
        type: 'object',
        properties: {url: {type: 'string', pattern: URL_SOURCE}, tokenEnv: {type: 'string', pattern: ENV_SOURCE}},
      },
    },
    // Image repositories a container service may run (image.repository).
    repository() {
      const name = {type: 'string', pattern: unicodePattern(tables.IMAGE_REPOSITORY.source)};
      return {
        description: 'An image repository without a tag or digest (ghcr.io/owner/name), or a list of them',
        anyOf: [name, {type: 'array', minItems: 1, items: name}],
      };
    },
    // Other attester implementations, with the binaries they may run as.
    attesters: () => ({
      description: 'Other attester implementations the verifier accepts evidence from; each needs sha256 or checksumsUrl',
      type: 'array',
      items: {
        ...convertTable(tables.ALLOWED_ATTESTER_SCHEMA, tables),
        anyOf: [{required: ['sha256']}, {required: ['checksumsUrl']}],
      },
    }),
    // Registry files (lib/registry.js).
    host: {
      description: 'A public host name or IPv4 address: not a private, loopback, link-local, shared or multicast address, nor a local name',
      type: 'string',
      // HOST, after lookaheads for what lib/registry.js refuses.
      pattern: String.raw`^(?!(?:0|10|127)\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|(?:22[4-9]|2[3-5]\d)\.|localhost$|.*\.(?:localhost|local|internal|home\.arpa)$|\[)` + unicodePattern(require('../lib/config').SCHEMAS.HOST.source).slice(1),
    },
    hostKeys: {
      description: 'The server\'s SSH host keys, as in /etc/ssh/ssh_host_ed25519_key.pub ("ssh-ed25519 AAAA...") or as ssh-keyscan prints them',
      type: 'array',
      minItems: 1,
      items: {type: 'string', pattern: String.raw`^(?:\S+\s+)?(?:ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+[A-Za-z\d+/]{44,}={0,2}(?:\s.*)?$`},
    },
    allowUntracked: {
      description: 'Patterns of files allowed though not in the commit; none may match every file',
      type: 'array',
      // A character other than *, / and . (those alone match every file).
      items: {type: 'string', pattern: String.raw`[^*/.]`},
    },
    // A function: SERVER_SCHEMA has custom checks of its own.
    servers: () => ({
      description: 'The servers to verify. Names must be unique.',
      type: 'array',
      minItems: 1,
      items: {
        ...convertTable(tables.SERVER_SCHEMA, tables),
        // Each transport needs its own settings (host for ssh, the default).
        // A null setting counts as missing, as in lib/config.js.
        anyOf: [
          {required: ['host'], properties: {transport: {enum: ['ssh', null]}, host: {type: 'string'}}},
          {required: ['transport', 'attesterConfig'], properties: {transport: {const: 'local'}, attesterConfig: {type: 'string'}}},
          {
            required: ['transport', 'kubernetes'],
            properties: {
              transport: {const: 'kubernetes'},
              kubernetes: {
                type: 'object',
                anyOf: [{required: ['node'], properties: {node: {type: 'string'}}}, {required: ['pod'], properties: {pod: {type: 'string'}}}],
              },
            },
          },
        ],
      },
    }),
  };
  if (!map[key]) {
    throw new Error(`lib/config.js has a custom check for "${key}" that scripts/build-site.js cannot describe as JSON Schema`);
  }

  return typeof map[key] === 'function' ? map[key]() : map[key];
}

// A missing setting and a null one are the same to lib/config.js.
function nullable(schema) {
  if (schema.enum) {
    return {...schema, enum: [...schema.enum, null]};
  }

  if (typeof schema.type === 'string') {
    return {...schema, type: [schema.type, 'null']};
  }

  return {anyOf: [schema, {type: 'null'}]};
}

// JSON Schema patterns are Unicode-mode regular expressions, where a brace
// that is not a quantifier must be escaped.
function unicodePattern(source) {
  let out = '';
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (char === '\\') {
      out += char + source[i + 1];
      i++;
    } else if (inClass) {
      inClass = char !== ']';
      out += char;
    } else {
      switch (char) {
        case '[': {
          inClass = true;
          out += char;

          break;
        }

        case '{': {
          const quantifier = /^{\d+(?:,\d*)?}/.exec(source.slice(i));
          out += quantifier ? quantifier[0] : String.raw`\{`;
          i += quantifier ? quantifier[0].length - 1 : 0;

          break;
        }

        case '}':
        case ']': {
          out += `\\${char}`;

          break;
        }

        default: {
          out += char;
        }
      }
    }
  }

  new RegExp(out, 'u');
  return out;
}

function convertField(key, [type, , extra], tables) {
  const pattern = extra instanceof RegExp ? {pattern: unicodePattern(extra.source)} : {};
  switch (type) {
    case 'string': {
      return {type: 'string', minLength: 1, ...pattern};
    }

    case 'boolean': {
      return {type: 'boolean'};
    }

    case 'integer': {
      return {type: 'integer', minimum: extra[0], maximum: extra[1]};
    }

    case 'enum': {
      return {enum: extra};
    }

    case 'strings': {
      return {type: 'array', items: {type: 'string', minLength: 1, ...pattern}};
    }

    case 'pcrs': {
      return {type: 'array', minItems: 1, items: {type: 'integer', minimum: 0, maximum: 23}};
    }

    case 'object': {
      return convertTable(extra, tables);
    }

    case 'list': {
      return {type: 'array', items: convertTable(extra, tables)};
    }

    default: {
      return customSchema(key, tables);
    }
  }
}

function convertTable(table, tables) {
  const properties = {};
  const required = [];
  for (const [key, field] of Object.entries(table)) {
    const schema = convertField(key, field, tables);
    properties[key] = field[1] ? schema : nullable(schema);
    if (field[1]) {
      required.push(key);
    }
  }

  return {
    type: 'object', properties, ...(required.length > 0 ? {required} : {}), additionalProperties: false,
  };
}

function configSchemas() {
  const tables = configTables();
  const attester = convertTable(tables.ATTESTER_SCHEMA, tables);
  const verifier = convertTable(tables.VERIFIER_SCHEMA, tables);
  // What lib/config.js checks across settings. A null setting counts as
  // missing there, so each rule names the type it needs.
  // One service (projectRoot) or services, not both.
  attester.anyOf = [
    {
      required: ['services'],
      properties: {
        services: {type: 'array'}, projectRoot: {type: 'null'}, processes: {type: 'null'}, exclude: {type: 'null'},
      },
    },
    {required: ['projectRoot'], properties: {projectRoot: {type: 'string'}, services: {type: 'null'}}},
  ];
  // Each service is a directory (root) or containers (container).
  const service = attester.properties.services.items;
  service.oneOf = [
    {required: ['root'], properties: {root: {type: 'string'}}},
    {required: ['container'], properties: {container: {type: 'object'}}},
  ];
  service.properties.container.anyOf = ['name', 'id', 'image', 'label'].map(key => ({required: [key], properties: {[key]: {type: 'string'}}}));
  // A repository for every service: its own, the top-level one, or none
  // for a service checked by its image alone.
  verifier.anyOf = [
    {required: ['repository'], properties: {repository: {type: 'object'}}},
    {
      required: ['services'],
      properties: {
        services: {
          type: 'array',
          items: {anyOf: [{required: ['repository'], properties: {repository: {type: 'object'}}}, {required: ['image'], properties: {image: {type: 'object'}}}]},
        },
      },
    },
  ];
  // A server whose TPM (or IMA) is required must pin its attestation key.
  const {tpm} = verifier.properties.servers.items.properties;
  tpm.anyOf = [{properties: {required: {enum: [false, null]}, ima: {enum: [false, null]}}}, {required: ['publicKey'], properties: {publicKey: {type: 'string'}}}];
  const {REGISTRY_SCHEMA} = require('../lib/registry');
  const registry = convertTable(REGISTRY_SCHEMA, tables);
  registry.properties.servers.minItems = 1;
  registry.anyOf = verifier.anyOf;
  registry.properties.servers.items.properties.tpm.anyOf = tpm.anyOf;
  return {
    'attester.schema.json': {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: `${SITE.url}/schema/attester.schema.json`,
      title: 'Audit Status attester configuration',
      description: 'The attester configuration, /etc/auditstatus/config.yml on each server. Generated from lib/config.js. See https://auditstatus.com/docs/configuration/#attester-configuration',
      ...attester,
    },
    'verifier.schema.json': {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: `${SITE.url}/schema/verifier.schema.json`,
      title: 'Audit Status verifier configuration',
      description: 'The verifier configuration, auditstatus.config.yml in the repository that runs auditstatus verify. Generated from lib/config.js. See https://auditstatus.com/docs/configuration/#verifier-configuration',
      ...verifier,
    },
    'registry.schema.json': {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: `${SITE.url}/schema/registry.schema.json`,
      title: 'Audit Status registry file',
      description: 'A project in the public registry, registry/<project>.yml in the Audit Status repository. Generated from lib/registry.js. See https://auditstatus.com/docs/registry/#the-registry-file',
      ...registry,
    },
  };
}

// ---------------------------------------------------------------------------
// Language pages and the schema index

// One row per guide in docs/languages/README.md: language, lockfile,
// reference, what is verified, guide.
function languageRows() {
  const markdown = fs.readFileSync(path.join(root, 'docs/languages/README.md'), 'utf8');
  const rows = new Map();
  for (const line of markdown.split('\n')) {
    const cells = line.split('|').slice(1, -1).map(cell => cell.trim());
    const guide = cells.length === 5 ? /\(([\w-]+)\.md\)/.exec(cells[4]) : null;
    if (guide) {
      rows.set(guide[1], {
        language: cells[0], lockfile: cells[1], reference: cells[2], verified: cells[3],
      });
    }
  }

  return rows;
}

function languagePage(slug, rows, nav, pages) {
  const source = `docs/languages/${slug}.md`;
  const doc = nav.flatMap(g => g.pages).find(p => p.source === source);
  const row = rows.get(slug);
  const inline = text => new Marked().parseInline(text);
  const name = doc.label;
  const heading = slug === 'binaries' ? 'Verify compiled and bundled releases' : `Verify ${name} deployments`;
  const {toc} = renderMarkdown(doc.body, source, pages);
  const sections = toc.filter(t => t.depth === 2).map(t => `<li><a href="${doc.url}#${t.id}">${t.html}</a></li>`).join('');
  const others = [...rows.keys()].filter(other => other !== slug).map(other => {
    const page = nav.flatMap(g => g.pages).find(p => p.source === `docs/languages/${other}.md`);
    return `<li><a href="/languages/${other}/">${esc(page ? page.label : other)}</a></li>`;
  }).join('');
  const lede = doc.body.split(/\n\s*\n/).map(s => s.trim()).find(s => s && !/^[#|`>\-*!<\d]/.test(s)) || '';
  const url = `/languages/${slug}/`;
  const body = `<div class="wrap guide">
<main id="main" class="doc">
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">${SITE.name}</a></li><li><a href="/docs/languages/">Languages</a></li><li><span aria-current="page">${esc(name)}</span></li></ol></nav>
<article class="prose">
<h1>${esc(heading)}</h1>
<p>${inline(lede)}</p>
${row
  ? `<div class="table-wrap"><table class="facts"><tbody>
<tr><th scope="row">Lockfile</th><td>${inline(row.lockfile)}</td></tr>
<tr><th scope="row">Reference</th><td>${inline(row.reference)}</td></tr>
<tr><th scope="row">What is verified</th><td>${inline(row.verified)}</td></tr>
</tbody></table></div>`
  : ''}
<h2 id="how-it-works">How it works</h2>
<p>The lockfile is read at the deployed commit, from the verifier's own clone of the public repository, never from the server. Every package is compared with the reference the lockfile pins, fetched and checked by hash. Besides the packages, the deployed files are compared with the commit, every process of the service is inspected, and every running executable and library is explained by a reference. A reference that cannot be fetched makes the result inconclusive, never passing.</p>
<h2 id="the-guide">The ${esc(name)} guide</h2>
<p>The <a href="${doc.url}">${esc(name)} guide</a> covers the setup for the project, the attester and the verifier:</p>
<ul>${sections}</ul>
<p><a class="button" href="${doc.url}">Read the ${esc(name)} guide</a></p>
<h2 id="other-languages">Other languages</h2>
<ul class="inline-list">${others}</ul>
</article>
</main>
<div class="toc toc-empty"></div>
</div>`;
  const description = truncate(`How Audit Status verifies ${slug === 'binaries' ? 'compiled and bundled releases' : `${name} deployments`}: ${plain(row ? `${row.verified}, compared with ${row.reference}` : lede)}.`.replace(/\.\.$/, '.'), 158);
  return {
    url,
    kind: 'language',
    active: 'languages',
    title: `${heading} — ${SITE.name}`,
    heading,
    label: name,
    description,
    keywords: `${name}, ${plain(row ? row.lockfile : '')}, production verification, lockfile, remote attestation`,
    sources: [source, 'docs/languages/README.md'],
    crumbs: [{name: SITE.name, url: '/'}, {name: 'Languages', url: '/docs/languages/'}, {name, url}],
    markdown: null,
    body,
  };
}

function schemaPage() {
  const rows = [
    ['attester.schema.json', 'Attester configuration', '/etc/auditstatus/config.yml on each server'],
    ['verifier.schema.json', 'Verifier configuration', 'auditstatus.config.yml in the repository that runs the verification'],
    ['registry.schema.json', 'Registry file', 'registry/&lt;project&gt;.yml in the public registry'],
    ['report.schema.json', 'Report', 'report.json, written by every verification'],
    ['report.example.json', 'Example report', 'A report from a verification of a test deployment'],
  ].map(([file, name, use]) => `<tr><td><a href="/schema/${file}">${name}</a></td><td><code>${file}</code></td><td>${use}</td></tr>`).join('\n');
  const body = `<div class="wrap guide">
<main id="main" class="doc">
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">${SITE.name}</a></li><li><span aria-current="page">JSON Schemas</span></li></ol></nav>
<article class="prose">
<h1>JSON Schemas</h1>
<p>JSON Schema 2020-12 definitions of the configuration files, the registry's files and the report. The configuration schemas are generated from the validation in <code>lib/config.js</code> and <code>lib/registry.js</code>, so they accept what <code>auditstatus validate</code> and <code>auditstatus registry validate</code> accept.</p>
<div class="table-wrap"><table><thead><tr><th>Schema</th><th>File</th><th>Describes</th></tr></thead><tbody>
${rows}
</tbody></table></div>
<h2 id="editor-support">Editor support</h2>
<p>Editors with the YAML language server validate and complete a configuration file that names its schema on the first line:</p>
${codeBlock('# yaml-language-server: $schema=https://auditstatus.com/schema/attester.schema.json\nversion: 2\nservices:\n  - name: web\n    root: /var/www/production/current', 'yaml', '/etc/auditstatus/config.yml')}
${codeBlock('# yaml-language-server: $schema=https://auditstatus.com/schema/verifier.schema.json\nversion: 2\nservers:\n  - name: web1\n    host: web1.example.com', 'yaml', 'auditstatus.config.yml')}
<p>Some settings are checked beyond what the schemas express: service and server names must be unique, a server's <code>services</code> must name services the file defines, a TPM key is pinned for one server only, and paths are resolved against the file's directory. See <a href="/docs/configuration/">Configuration</a>.</p>
</article>
</main>
<div class="toc toc-empty"></div>
</div>`;
  return {
    url: '/schema/',
    kind: 'page',
    active: 'docs',
    title: `JSON Schemas — ${SITE.name}`,
    heading: 'JSON Schemas',
    description: 'JSON Schemas for the Audit Status attester and verifier configuration files and for report.json, with editor support through the YAML language server.',
    sources: ['lib/config.js', 'lib/registry.js', 'site/schema/report.schema.json'],
    crumbs: [{name: SITE.name, url: '/'}, {name: 'JSON Schemas', url: '/schema/'}],
    markdown: null,
    body,
  };
}

// ---------------------------------------------------------------------------
// The registry's projects, with their live badges (Shields.io reads each
// project's badge.json on the status branch, so the page needs no rebuild
// when a status changes).

function projectsPage() {
  const registry = require('../lib/registry');
  const dir = path.join(root, 'registry');
  const rows = registry.listProjects(dir).map(slug => {
    const {raw} = registry.readProject(slug, dir);
    const repositories = [...new Set([raw.repository, ...(raw.services || []).map(service => service.repository)]
      .filter(Boolean).map(repository => repository.url.replace(/\.git$/, '')))];
    const description = raw.project.description ? `<br><span class="muted">${esc(raw.project.description)}</span>` : '';
    const sources = repositories.map(url => `<a href="${esc(url)}">${esc(url.replace(/^https:\/\/(?:github\.com\/)?/, ''))}</a>`).join('<br>');
    const badge = `<a href="${esc(registry.links.report(slug))}"><img src="${esc(registry.links.badge(slug))}" alt="${esc(raw.project.name)}: audit status" width="220" height="20" style="object-fit:contain;object-position:left center" loading="lazy"></a>`;
    return `<tr><td><a href="${esc(raw.project.url)}">${esc(raw.project.name)}</a>${description}</td><td>${sources}</td><td>${badge}</td><td><a href="${SITE.repo}/blob/${SITE.branch}/registry/${slug}.yml"><code>${slug}.yml</code></a></td></tr>`;
  });
  const body = `<div class="wrap guide">
<main id="main" class="doc">
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">${SITE.name}</a></li><li><span aria-current="page">Verified projects</span></li></ol></nav>
<article class="prose">
<h1>Verified projects</h1>
<p>The <a href="/docs/registry/">public registry</a> verifies these projects' production servers every hour from GitHub Actions, as a third party: the deployed files against the public repository, the packages against the lockfile, the build against a reproduced build. Each badge shows the latest result and links to its signed report.</p>
<div class="table-wrap"><table><thead><tr><th>Project</th><th>Source</th><th>Status</th><th>Registry file</th></tr></thead><tbody>
${rows.join('\n') || '<tr><td colspan="4">No project is in the registry yet.</td></tr>'}
</tbody></table></div>
<p>Every result as JSON: <a href="https://raw.githubusercontent.com/${registry.REPOSITORY}/${registry.STATUS_BRANCH}/index.json"><code>index.json</code></a> on the <a href="${SITE.repo}/tree/${registry.STATUS_BRANCH}"><code>${registry.STATUS_BRANCH}</code> branch</a>, which the registry's workflow writes each hour.</p>
<h2 id="add-yours">Add yours</h2>
<p>One YAML file in <code>registry/</code> and Audit Status's SSH key on your servers. Nothing runs in your CI. See <a href="/docs/registry/#add-your-project">Add your project</a>.</p>
</article>
</main>
<div class="toc toc-empty"></div>
</div>`;
  return {
    url: '/projects/',
    kind: 'page',
    active: 'docs',
    title: `Verified projects — ${SITE.name}`,
    heading: 'Verified projects',
    description: 'Open-source projects whose production servers Audit Status verifies every hour from GitHub Actions, with their live status badges and signed reports.',
    sources: ['registry', 'lib/registry.js'],
    crumbs: [{name: SITE.name, url: '/'}, {name: 'Verified projects', url: '/projects/'}],
    markdown: null,
    body,
  };
}

// ---------------------------------------------------------------------------
// Landing page

const STATUS = {
  pass: ['passing', 'Every check ran and matched its reference.'],
  warn: ['passing with warnings', 'Passed, with findings worth attention. Counts as passed.'],
  fail: ['failing', 'The server differs from its references, or its evidence is invalid.'],
  error: ['inconclusive', 'A check could not be completed. Never counts as passing.'],
};

// [server, status, evidence level, services, processes, code explained]
const SAMPLE = [
  ['web1', 'pass', 'TPM + IMA', 1, 12, '184/184'],
  ['web2', 'warn', 'TPM', 1, 12, '181/184'],
  ['worker1', 'fail', 'Software evidence', 2, 6, '97/98'],
  ['db1', 'error', 'AMD SEV-SNP', 1, 3, '41/41'],
];

// [name, what is read, document]
const LANGUAGES = [
  ['Node.js', 'package-lock.json, pnpm-lock.yaml', 'docs/languages/node.md'],
  ['Python', 'uv.lock, poetry.lock, pylock.toml, hashed requirements', 'docs/languages/python.md'],
  ['Ruby', 'Gemfile.lock with checksums', 'docs/languages/ruby.md'],
  ['Elixir', 'mix.lock', 'docs/languages/elixir.md'],
  ['PHP', 'composer.lock', 'docs/languages/php.md'],
  ['Java', 'Gradle verification metadata, Maven lockfile', 'docs/languages/java.md'],
  ['.NET', 'packages.lock.json', 'docs/languages/dotnet.md'],
  ['Go', 'go.sum and the binary\'s build information', 'docs/languages/go.md'],
  ['Rust', 'Cargo.lock and cargo-auditable data', 'docs/languages/rust.md'],
  ['Releases', 'Attested manifests, signed checksums', 'docs/languages/binaries.md'],
];

// [level, backed by, holds against root on the server, strength 1-4]
const LEVELS = [
  ['Software evidence', 'The attester\'s report, bound to a fresh nonce by its digest.', 'No.', 1],
  ['TPM', 'A TPM 2.0 quote over the nonce and digest, with an enrolled key; boot state with pinned PCR values.', 'No: it proves freshness and which machine answered.', 2],
  ['TPM + IMA', 'The kernel\'s measurement log, replayed to the quoted PCR 10.', 'For the files the IMA policy measures.', 3],
  ['AMD SEV-SNP, Intel TDX', 'A confidential VM report signed by the CPU vendor.', 'Protects against the host operator, not against root in the guest.', 3],
];

// [title, text, document]
const DEPLOY = [
  ['SSH and one binary', 'Install the release binary on each server. The verifier connects with a key restricted to a forced command that can only run the attester.', 'docs/attester.md#the-ssh-forced-command'],
  ['Ansible', 'A role installs the attester, its account, configuration and SSH key the same way on every server.', 'docs/attester.md#the-ansible-role'],
  ['Kubernetes', 'A Helm chart runs the attester as a DaemonSet. The verifier reaches it through port-forward: no Service, no open port.', 'docs/kubernetes.md#the-helm-chart'],
  ['GitHub Action', 'The verifier runs on a schedule, writes the report to the job summary, publishes it to a branch and manages an issue.', 'docs/verifier.md#the-github-action'],
];

const LEDGER = [
  ['evidence', 'Nonce and digest match'],
  ['tpm', 'Quote by the enrolled key'],
  ['source', '1,204 of 1,204 files match the commit'],
  ['packages', 'npm: 812 of 812 verified'],
  ['process', '12 processes inspected'],
  ['code', '184 of 184 running files explained'],
];

function status(key) {
  return `<span class="status st-${key}"><span class="dot" aria-hidden="true"></span>${STATUS[key][0]}</span>`;
}

function term(text, tip, id) {
  return `<span class="term" tabindex="0" aria-describedby="${id}">${text}<span class="tip" role="tooltip" id="${id}">${esc(tip)}</span></span>`;
}

function landing(pages) {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const shell = [...readme.matchAll(/```sh\n([\s\S]*?)```/g)].map(m => m[1]);
  const registryFile = /```yaml\n([\s\S]*?)```/.exec(readme);
  const {links: registryLinks} = require('../lib/registry');
  const badge = `[![Audit Status](${registryLinks.badge('example')})](${registryLinks.report('example')})`;
  const link = href => rewriteLink(href, 'README.md', pages);

  const ledger = LEDGER.map(([check, text]) => `<li><code>${check}</code><span>${text}</span>${CHECK}</li>`).join('\n');
  const rows = SAMPLE.map(([server, key, level, services, processes, code]) => `<tr><td><code>${server}</code></td><td>${status(key)}</td><td>${level}</td><td class="num">${services}</td><td class="num">${processes}</td><td class="num">${code}</td></tr>`).join('\n');
  const legend = Object.keys(STATUS).map(key => `<li>${term(status(key), STATUS[key][1], `st-tip-${key}`)}</li>`).join('');
  const languages = LANGUAGES.map(([name, lock, href]) => `<li><a href="/languages/${path.basename(href, '.md')}/"><span class="lang-name">${name}</span><span class="lang-lock">${lock}</span></a></li>`).join('\n');
  const levels = LEVELS.map(([name, backed, holds, strength]) => `<tr><th scope="row"><span class="meter" aria-hidden="true">${[1, 2, 3, 4].map(n => `<span${n <= strength ? ' class="on"' : ''}></span>`).join('')}</span>${name}</th><td data-label="Backed by">${backed}</td><td data-label="Holds against root">${holds}</td></tr>`).join('\n');
  const deploy = DEPLOY.map(([title, text, href]) => `<li><h3>${title}</h3><p>${text}</p><a href="${link(href)}">${title === 'GitHub Action' ? 'The action' : 'Set it up'}<span class="sr-only">: ${title}</span></a></li>`).join('\n');

  const body = `<main id="main">
<section class="hero">
<div class="wrap hero-grid">
<div class="hero-text">
<h1>Proof that production runs the public code.</h1>
<p class="lede">Audit Status verifies that production servers run exactly the code in a public repository, and publishes a report and a badge.</p>
<p class="lede-2">Open source shows what a service could run. Audit Status shows what it does run, checked against references the server does not control.</p>
<div class="install">
<code><span class="prompt" aria-hidden="true">$ </span>npm install -g auditstatus</code>
<button class="copy" type="button" data-copy="npm install -g auditstatus">Copy</button>
</div>
<p class="hero-links"><a class="button" href="/docs/registry/#add-your-project">Add your project</a><a class="button button-quiet" href="/docs/how-it-works/">How it works</a></p>
</div>
<figure class="ledger">
<div class="ledger-head"><code>web1.example.com</code>${status('pass')}</div>
<ol>
${ledger}
</ol>
<figcaption><span>Evidence level</span> TPM + IMA</figcaption>
</figure>
</div>
</section>

<section class="section" id="quick-start" aria-labelledby="quick-start-h">
<div class="wrap">
<div class="section-head">
<h2 id="quick-start-h">Quick start</h2>
<p>Add your project to the <a href="/docs/registry/">public registry</a>: Audit Status verifies your servers every hour from its own GitHub Actions and publishes your report and badge. Nothing runs in your CI.</p>
</div>
<ol class="steps">
<li>
<div class="step-text"><span class="step-n">1</span><h3>On each server</h3><p>Install the attester, allow Audit Status's SSH key to run the attester and nothing else, and check the setup.</p></div>
${shell[0] ? codeBlock(shell[0], 'sh') : ''}
</li>
<li>
<div class="step-text"><span class="step-n">2</span><h3>In the registry</h3><p>Add one YAML file to <code>registry/</code> in a pull request: your project, its repository, where it is deployed, and each server with its SSH host key.</p></div>
${registryFile ? codeBlock(registryFile[1], 'yaml', 'registry/example.yml') : ''}
</li>
<li>
<div class="step-text"><span class="step-n">3</span><h3>Every hour</h3><p>The registry collects evidence from each server, compares it with the public references, and publishes a signed report and a badge for your README or status page.</p></div>
${codeBlock(badge, '', 'README.md')}
</li>
</ol>
<p class="note">To run the verifier in your own CI instead, <a href="/docs/getting-started/">Getting started</a> walks through <code>auditstatus init</code> and the GitHub action.</p>
</div>
</section>

<section class="section" id="report" aria-labelledby="report-h">
<div class="wrap">
<div class="section-head">
<h2 id="report-h">The report</h2>
<p>Each run writes <code>report.md</code> for people, <code>report.json</code> for machines and <code>badge.json</code> for a badge. A server's status is the worst of its findings; inconclusive never counts as passing. <a href="/docs/reports/">Reading a report</a></p>
</div>
<figure class="report">
<div class="report-head"><span class="report-file">report.md</span><span>${status('fail')}<span class="report-sum">2 of 4 servers passed</span></span></div>
<div class="table-wrap">
<table>
<thead><tr><th scope="col">Server</th><th scope="col">Status</th><th scope="col">${term('Evidence', 'The evidence level: software evidence, TPM, TPM + IMA, AMD SEV-SNP or Intel TDX.', 'col-evidence')}</th><th scope="col" class="num">Services</th><th scope="col" class="num">${term('Processes', 'Application processes inspected across the services.', 'col-processes')}</th><th scope="col" class="num">${term('Code explained', 'Executables and libraries that matched a reference, out of all those the processes run or map.', 'col-code')}</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</div>
<div class="finding"><span class="sev sev-fail">fail</span><code>source</code><span>worker1, service <code>queue</code>: Files differ from the public commit: <code>lib/jobs.js</code></span></div>
<figcaption>An example report. The badge and a status page read the same result.</figcaption>
</figure>
<ul class="status-legend" aria-label="Statuses">${legend}</ul>
</div>
</section>

<section class="section" id="languages" aria-labelledby="languages-h">
<div class="wrap">
<div class="section-head">
<h2 id="languages-h">Languages and ecosystems</h2>
<p>For every service, the deployed files are compared with the public commit and every running executable and library is explained by a reference. Installed packages are checked against the lockfile at the deployed commit, read from the verifier's own clone.</p>
</div>
<ul class="languages">
${languages}
</ul>
<p class="note">Containers (Docker, containerd, CRI-O, Podman) are compared with their images, fetched by digest. System binaries and libraries are compared with the signed Debian or Ubuntu archive. <a href="/docs/containers/">Containers</a></p>
</div>
</section>

<section class="section" id="evidence-levels" aria-labelledby="levels-h">
<div class="wrap">
<div class="section-head">
<h2 id="levels-h">Evidence levels</h2>
<p>The report and the badge show the level of every result. Software evidence catches drift, failed deploys and tampering by anyone without root, but root on the server can forge it; hardware makes the evidence hold against more. <a href="/docs/how-it-works/#a-forged-answer">A forged answer</a> <a href="/docs/threat-model/">Threat model</a></p>
</div>
<div class="table-wrap">
<table class="levels">
<thead><tr><th scope="col">Level</th><th scope="col">Backed by</th><th scope="col">Holds against root on the server</th></tr></thead>
<tbody>
${levels}
</tbody>
</table>
</div>
</div>
</section>

<section class="section" id="deployment" aria-labelledby="deploy-h">
<div class="wrap">
<div class="section-head">
<h2 id="deploy-h">Deployment</h2>
<p>The attester is one executable with no runtime dependencies. It only reads: it never executes what it inspects.</p>
</div>
<ul class="deploy">
${deploy}
</ul>
</div>
</section>

<section class="section" id="related" aria-labelledby="related-h">
<div class="wrap">
<div class="section-head">
<h2 id="related-h">Open by design</h2>
<p>The format, the verifier and the configuration are public, so anyone can check the result or run the verification themselves.</p>
</div>
<div class="compare">
<div>
<h3>Built on Attestium</h3>
<p>The evidence format and every check come from Attestium, an open library and specification for remote attestation. An attester or verifier in another language interoperates by following it.</p>
<p><a href="https://attestium.com">attestium.com</a></p>
</div>
<div>
<h3>First project: Forward Email</h3>
<p>Forward Email deploys its public repository with git and PM2. Every hour the registry checks its production servers against the latest release, and its status page shows the result.</p>
<p><a href="/projects/">Projects</a> <a href="https://status.forwardemail.net">status.forwardemail.net</a></p>
</div>
</div>
<div class="credit">
<a class="credit-logo" href="https://forwardemail.net"><img src="https://forwardemail.net/img/logo-square.svg" width="44" height="44" alt="Forward Email"></a>
<p>A project by <a href="https://forwardemail.net">Forward Email</a>, the open-source, privacy-focused email service. <a href="/docs/adopters/">Adopt Audit Status</a></p>
</div>
</div>
</section>
</main>`;

  return {
    url: '/',
    kind: 'home',
    title: `${SITE.name} — ${SITE.tagline}`,
    description: SITE.description,
    keywords: SITE.keywords,
    sources: ['README.md', 'docs/verifier.md', 'scripts/build-site.js'],
    body,
    markdown: null,
  };
}
// ---------------------------------------------------------------------------
// Docs pages

function sidebar(nav, current) {
  return nav.map(({group, pages}) => `<div class="side-group"><h2>${group}</h2><ul>${pages.map(p => `<li><a href="${p.url}"${p.source === current ? ' aria-current="page"' : ''}>${esc(p.label)}</a></li>`).join('')}</ul></div>`).join('\n');
}

function tocNav(toc) {
  return toc.length > 1
    ? `<nav class="toc" aria-labelledby="toc-h"><h2 id="toc-h">On this page</h2><ul>${toc.map(t => `<li class="toc-${t.depth}"><a href="#${t.id}">${t.html}</a></li>`).join('')}</ul></nav>`
    : '<div class="toc toc-empty"></div>';
}

function activeKey(source) {
  if (source === 'docs/reports.md') {
    return 'reports';
  }

  return source.startsWith('docs/languages/') ? 'languages' : 'docs';
}

function docPage(doc, nav, order, pages) {
  const index = order.indexOf(doc);
  const prev = order[index - 1];
  const next = order[index + 1];
  const {html, toc} = renderMarkdown(doc.body, doc.source, pages);
  const pager = `<nav class="pager" aria-label="Previous and next page">${prev ? `<a class="prev" href="${prev.url}"><span>Previous</span>${esc(prev.label)}</a>` : '<span></span>'}${next ? `<a class="next" href="${next.url}"><span>Next</span>${esc(next.label)}</a>` : ''}</nav>`;
  const body = `<div class="wrap docs">
<aside class="sidebar">
<button class="side-toggle" type="button" aria-expanded="false" aria-controls="side-nav"><span><span class="muted">Docs /</span> ${esc(doc.label)}</span><svg viewBox="0 0 20 20" aria-hidden="true"><path d="m6 8 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
<nav id="side-nav" class="side-nav" aria-label="Documentation">
${sidebar(nav, doc.source)}
</nav>
</aside>
<main id="main" class="doc">
<article class="prose">
<h1>${doc.titleHtml}</h1>
${addGlossary(html, 'g')}
</article>
<p class="edit"><a href="${SITE.repo}/blob/${SITE.branch}/${doc.source}" rel="noopener">Edit this page on GitHub</a></p>
${pager}
</main>
${tocNav(toc)}
</div>`;
  const language = doc.source.startsWith('docs/languages/') && doc.url !== '/docs/languages/';
  const crumbs = [{name: SITE.name, url: '/'}, {name: 'Documentation', url: '/docs/'}];
  if (language) {
    crumbs.push({name: 'Languages', url: '/docs/languages/'});
  }

  if (doc.url !== '/docs/') {
    crumbs.push({name: doc.label, url: doc.url});
  }

  return {
    url: doc.url,
    kind: 'doc',
    active: activeKey(doc.source),
    title: doc.title.includes(SITE.name) ? doc.title : `${doc.title} — ${SITE.name}`,
    heading: doc.title,
    description: doc.description,
    sources: [doc.source],
    crumbs,
    markdown: markdownCopy(doc.title, doc.body, doc.source, pages, doc.url),
    group: language ? 'Languages' : 'Documentation',
    body,
  };
}

function loadDoc(source, label) {
  const markdown = fs.readFileSync(path.join(root, source), 'utf8');
  const titleMatch = /^# (.+)$/m.exec(markdown);
  const title = titleMatch ? plain(titleMatch[1]) : path.basename(source, '.md');
  const body = titleMatch ? markdown.slice(titleMatch.index + titleMatch[0].length) : markdown;
  const paragraph = body.split(/\n\s*\n/).map(s => s.trim()).find(s => s && !/^[#|`>\-*!<\d]/.test(s)) || SITE.description;
  const titleHtml = titleMatch ? new Marked().parseInline(titleMatch[1]) : esc(title);
  return {
    source, url: urlFor(source), title, titleHtml, label: label || title, description: truncate(plain(paragraph), 158), body,
  };
}

// A document as Markdown for agents: links made absolute, nothing else changed.
function markdownCopy(title, body, source, pages, url) {
  const absolute = href => {
    const target = rewriteLink(href, source, pages);
    if (target.startsWith('#')) {
      return `${SITE.url}${url}${target}`;
    }

    return target.startsWith('/') ? SITE.url + target : target;
  };

  const text = body.split(/(```[\s\S]*?```)/).map(part => (part.startsWith('```')
    ? part
    : part.replaceAll(/(!?\[[^\]]*])\(([^)\s]+)((?:\s+"[^"]*")?)\)/g, (match, label, href, title) => `${label}(${absolute(href)}${title})`))).join('');
  return `# ${title}\n\n${text.trim()}\n`;
}

// ---------------------------------------------------------------------------
// Guides, FAQ and brand pages

function frontMatter(text) {
  // Page metadata sits in an HTML comment at the top, which Markdown tools leave alone.
  const match = /^<!--\n([\s\S]*?)\n-->\n/.exec(text);
  const data = {};
  for (const line of match ? match[1].split('\n') : []) {
    const index = line.indexOf(':');
    if (index > 0) {
      data[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
  }

  return {data, body: match ? text.slice(match[0].length) : text};
}

function guidePage(slug, pages, guides) {
  const source = `site/pages/${slug}.md`;
  const {data, body: markdown} = frontMatter(fs.readFileSync(path.join(root, source), 'utf8'));
  const titleMatch = /^# (.+)$/m.exec(markdown);
  const heading = titleMatch ? plain(titleMatch[1]) : data.title;
  const body = titleMatch ? markdown.slice(titleMatch.index + titleMatch[0].length) : markdown;
  const url = `/${slug}/`;
  const {html, toc} = renderMarkdown(body, source, pages);
  const faq = slug === 'faq'
    ? body.split(/^## /m).slice(1).map(section => {
      const [question, ...rest] = section.split('\n');
      return {question: question.trim(), answer: stripTags(new Marked().parse(rest.join('\n'))).replaceAll(/\s+/g, ' ').trim()};
    })
    : null;
  const related = guides.filter(g => g.url !== url);
  const aside = `<aside class="related" aria-labelledby="related-h"><h2 id="related-h">${slug === 'faq' ? 'Guides' : 'More guides'}</h2><ul>${related.map(g => `<li><a href="${g.url}">${esc(g.label)}</a><span>${esc(g.description)}</span></li>`).join('')}</ul></aside>`;
  const label = data.label || heading;
  const bodyHtml = `<div class="wrap guide">
<main id="main" class="doc">
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">${SITE.name}</a></li><li><span aria-current="page">${esc(label)}</span></li></ol></nav>
<article class="prose">
<h1>${esc(heading)}</h1>
${addGlossary(html, 'g')}
</article>
<p class="edit"><a href="${SITE.repo}/blob/${SITE.branch}/${source}" rel="noopener">Edit this page on GitHub</a></p>
${aside}
</main>
${tocNav(toc)}
</div>`;
  return {
    url,
    kind: slug === 'faq' ? 'faq' : 'guide',
    active: slug === 'faq' ? 'faq' : 'guide',
    title: `${data.title || heading} — ${SITE.name}`,
    heading,
    label,
    description: data.description,
    keywords: data.keywords,
    sources: [source],
    crumbs: [{name: SITE.name, url: '/'}, {name: label, url}],
    markdown: markdownCopy(heading, body, source, pages, url),
    group: slug === 'faq' ? 'FAQ' : 'Guides',
    faq,
    body: bodyHtml,
  };
}

const COLORS = [
  ['Ink', '#1D3536', 'The tile, text, dark backgrounds'],
  ['Seafoam', '#7FB5A8', 'Tile border, rules'],
  ['Soft seafoam', '#8CC7BA', 'Ledger lines in the mark'],
  ['Cream', '#FCF0DE', 'The check; wordmark on dark'],
  ['Apricot', '#F2B988', 'The status dot'],
  ['Deep teal', '#236661', 'Links on light'],
  ['Paper', '#FBF7EF', 'Light background'],
];

function brandPage() {
  const files = [
    ['logo.svg', 'Logo', 'Mark and wordmark, for light backgrounds'],
    ['logo-dark.svg', 'Logo, dark', 'Mark and wordmark, for dark backgrounds'],
    ['mark.svg', 'Mark', 'The report tile, 48 pixels and larger'],
    ['favicon.svg', 'Small mark', 'The simplified tile, below 48 pixels'],
    ['mark-mono.svg', 'Monochrome mark', 'One color, follows currentColor'],
  ];
  const swatches = COLORS.map(([name, hex, use]) => `<li><span class="swatch-lg" style="background:${hex}"></span><span><strong>${name}</strong><code>${hex}</code><span class="muted">${use}</span></span></li>`).join('');
  const downloads = files.map(([file, name, use]) => `<li><a href="/brand/${file}" download>${name}</a><span class="muted">${use}</span></li>`).join('');
  const body = `<div class="wrap brand-page">
<main id="main" class="doc">
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">${SITE.name}</a></li><li><span aria-current="page">Brand</span></li></ol></nav>
<div class="prose">
<h1>Brand</h1>
<p>The Audit Status mark is a report tile: two ledger lines, a check, and a status dot. It shares its tile, border and corner radius with the <a href="https://attestium.com/brand/">Attestium mark</a>, the library Audit Status is built on. Use the files below as they are.</p>
</div>

<section class="brand-section" aria-labelledby="b-logo">
<h2 id="b-logo">Logo</h2>
<div class="brand-panels">
<figure class="panel panel-light">${svgInline('logo.svg', 'brand-logo')}<figcaption>On light</figcaption></figure>
<figure class="panel panel-dark">${svgInline('logo-dark.svg', 'brand-logo')}<figcaption>On dark</figcaption></figure>
</div>
</section>

<section class="brand-section" aria-labelledby="b-mark">
<h2 id="b-mark">Mark</h2>
<p>Use the full tile at 48 pixels and larger. Below that, the second line and the dot are too small to read: use the simplified tile, which is also the favicon.</p>
<div class="brand-sizes">
<figure>${svgInline('mark.svg', 'size-256')}<figcaption>Mark, 128 px</figcaption></figure>
<figure>${svgInline('mark.svg', 'size-64')}<figcaption>Mark, 64 px</figcaption></figure>
<figure>${svgInline('favicon.svg', 'size-32')}<figcaption>Small, 32 px</figcaption></figure>
<figure>${svgInline('favicon.svg', 'size-16')}<figcaption>Small, 16 px</figcaption></figure>
<figure class="mono">${svgInline('mark-mono.svg', 'size-64')}<figcaption>Monochrome</figcaption></figure>
</div>
</section>

<section class="brand-section" aria-labelledby="b-space">
<h2 id="b-space">Clear space and size</h2>
<div class="brand-split">
<figure class="clearspace">${svgInline('mark.svg', 'size-128')}<figcaption>Keep a quarter of the tile's width clear on every side.</figcaption></figure>
<ul class="brand-rules">
<li>Clear space: one quarter of the tile's width on every side, more where possible.</li>
<li>Minimum size: 48 pixels for the full mark, 16 pixels for the small mark, 120 pixels wide for the logo.</li>
<li>The wordmark sits to the right of the tile, its cap height half the tile's height.</li>
</ul>
</div>
</section>

<section class="brand-section" aria-labelledby="b-color">
<h2 id="b-color">Color</h2>
<ul class="swatches">${swatches}</ul>
<p class="muted">The SVG files take their colors from CSS custom properties when placed inline, with these values as defaults:</p>
${codeBlock(':root {\n  --auditstatus-tile: #1D3536;\n  --auditstatus-line: #7FB5A8;\n  --auditstatus-glyph: #FCF0DE;\n  --auditstatus-soft: #8CC7BA;\n  --auditstatus-accent: #F2B988;\n  --auditstatus-word: #1D3536;\n}', 'css', 'CSS')}
</section>

<section class="brand-section" aria-labelledby="b-type">
<h2 id="b-type">Type</h2>
<dl class="type-specimens">
<div><dt>IBM Plex Sans, semibold</dt><dd class="spec-serif">Headings and the wordmark</dd></div>
<div><dt>System sans-serif</dt><dd class="spec-sans">Body text, at the reader's system font</dd></div>
<div><dt>IBM Plex Mono</dt><dd class="spec-mono">Code, commands and check names</dd></div>
</dl>
</section>

<section class="brand-section" aria-labelledby="b-use">
<h2 id="b-use">Use</h2>
<div class="dos">
<div><h3>Do</h3><ul><li>Use the SVG files unchanged.</li><li>Use the dark logo on dark backgrounds.</li><li>Use the monochrome mark where only one color can print.</li><li>Link the mark to auditstatus.com or to the published report.</li></ul></div>
<div><h3>Do not</h3><ul><li>Stretch, rotate or outline the mark.</li><li>Recolor the tile outside the palette, or add gradients and shadows.</li><li>Use the status dot to show a live status: it is part of the mark, not a signal.</li><li>Set the wordmark in another typeface.</li><li>Use the full tile below 48 pixels.</li></ul></div>
</div>
</section>

<section class="brand-section" aria-labelledby="b-files">
<h2 id="b-files">Files</h2>
<ul class="downloads">${downloads}<li><a href="/icon-512.png" download>App icon</a><span class="muted">PNG, 512 by 512</span></li></ul>
</section>
</main>
</div>`;
  return {
    url: '/brand/',
    kind: 'brand',
    active: 'brand',
    title: `Brand — ${SITE.name}`,
    heading: 'Brand',
    description: 'The Audit Status logo, mark, colors and type: SVG downloads, clear space, minimum sizes and how to use them.',
    sources: ['site/brand/logo.svg', 'site/brand/mark.svg'],
    crumbs: [{name: SITE.name, url: '/'}, {name: 'Brand', url: '/brand/'}],
    markdown: null,
    body,
  };
}

function notFound() {
  return {
    url: '/404.html',
    kind: 'error',
    title: `Page not found — ${SITE.name}`,
    description: 'Nothing is published at this address. The documentation, the guides and the language pages are linked from the home page.',
    sources: [],
    markdown: null,
    body: `<main id="main" class="wrap not-found">
${svgInline('mark.svg', 'not-found-mark')}
<h1>Page not found</h1>
<p>Nothing is published at this address.</p>
<p class="hero-links"><a class="button" href="/">Home</a><a class="button button-quiet" href="/docs/">Documentation</a></p>
</main>`,
  };
}

// ---------------------------------------------------------------------------
// Files for search engines and agents

const lastModified = new Map();
function lastmod(sources, fallback) {
  const dates = sources.map(source => {
    if (!lastModified.has(source)) {
      let date = '';
      try {
        date = execFileSync('git', ['-C', root, 'log', '-1', '--format=%cI', '--', source], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim();
      } catch {}

      lastModified.set(source, date);
    }

    return lastModified.get(source);
  }).filter(Boolean).sort();
  return dates.length > 0 ? dates.at(-1) : fallback;
}

function robots() {
  return `# Everything on this site is public. Search engines, crawlers and AI agents are welcome;\n# ${SITE.url}/llms.txt lists the pages for language models.\nUser-agent: *\nAllow: /\n\nSitemap: ${SITE.url}/sitemap.xml\n`;
}

function sitemap(pages) {
  const entries = pages.filter(p => p.kind !== 'error').map(p => `<url><loc>${SITE.url}${p.url}</loc><lastmod>${p.lastmod}</lastmod></url>`);
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries.join('\n')}\n</urlset>\n`;
}

function llms(pages) {
  const link = p => `- [${p.heading || p.title}](${SITE.url}${p.url}index.md): ${p.description}`;
  const group = name => pages.filter(p => p.group === name && p.markdown).map(p => link(p)).join('\n');
  return `# ${SITE.name}

> ${SITE.description}

Audit Status is one binary with two roles: an attester on each server, invoked by the verifier over SSH with a forced command (or through kubectl port-forward), and a verifier that runs in CI, compares the evidence with references it fetches itself, and writes report.md, report.json and a badge. It is built on Attestium. Each link below is the Markdown source of a page.

## Documentation

${group('Documentation')}

## Languages

${group('Languages')}

## Guides

${group('Guides')}
${group('FAQ')}

## Schemas

- [Attester configuration schema](${SITE.url}/schema/attester.schema.json): JSON Schema for /etc/auditstatus/config.yml
- [Verifier configuration schema](${SITE.url}/schema/verifier.schema.json): JSON Schema for auditstatus.config.yml
- [Registry file schema](${SITE.url}/schema/registry.schema.json): JSON Schema for registry/<project>.yml in the public registry
- [Report schema](${SITE.url}/schema/report.schema.json): JSON Schema for report.json, with an [example](${SITE.url}/schema/report.example.json)

## Optional

- [All documentation in one file](${SITE.url}/llms-full.txt): every page above, concatenated
- [Attestium](https://attestium.com/llms.txt): the library and evidence format Audit Status is built on
- [Source code](${SITE.repo}): the attester, the verifier, the Helm chart, the Ansible role and the GitHub action
`;
}

function llmsFull(pages) {
  return pages.filter(p => p.markdown).map(p => `<!-- ${SITE.url}${p.url} -->\n\n${p.markdown}`).join('\n\n');
}

function manifest() {
  return `${JSON.stringify({
    name: SITE.name,
    short_name: SITE.name,
    description: SITE.description,

    start_url: '/',
    scope: '/',
    display: 'browser',

    background_color: SITE.themeLight,

    theme_color: SITE.themeDark,
    icons: [
      {src: '/icon-192.png', sizes: '192x192', type: 'image/png'},
      {src: '/icon-512.png', sizes: '512x512', type: 'image/png'},
      {src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml'},
    ],
  }, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Build

function write(outDir, url, content) {
  const file = url.endsWith('/') ? path.join(outDir, url, 'index.html') : path.join(outDir, url);
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, content);
}

function copy(from, outDir, url) {
  const target = path.join(outDir, url);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.copyFileSync(from, target);
}

async function build({outDir = path.join(root, '_site')} = {}) {
  ({Marked} = await import('marked'));
  fs.rmSync(outDir, {recursive: true, force: true});
  fs.mkdirSync(outDir, {recursive: true});
  const buildTime = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  const css = fs.readFileSync(path.join(siteDir, 'style.css'), 'utf8');
  const js = fs.readFileSync(path.join(siteDir, 'site.js'), 'utf8');
  const assets = {css: hash(css), js: hash(js)};
  fs.writeFileSync(path.join(outDir, 'style.css'), css);
  fs.writeFileSync(path.join(outDir, 'site.js'), js);
  for (const file of ['favicon-32.png', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png', 'og.png']) {
    copy(path.join(siteDir, file), outDir, file);
  }

  for (const file of fs.readdirSync(path.join(siteDir, 'brand')).filter(name => name.endsWith('.svg'))) {
    copy(path.join(siteDir, 'brand', file), outDir, `brand/${file}`);
  }

  copy(path.join(siteDir, 'brand', 'favicon.svg'), outDir, 'favicon.svg');

  // Navigation: configured pages first, then any other document in docs/.
  const listed = new Set(NAV.flatMap(g => g.pages.map(([source]) => source)));
  const extra = listDocs().filter(source => !listed.has(source));
  const groups = extra.length > 0 ? [...NAV, {group: 'More', pages: extra.map(source => [source])}] : NAV;
  const nav = groups.map(({group, pages}) => ({
    group,
    pages: pages.filter(([source]) => fs.existsSync(path.join(root, source))).map(([source, label]) => loadDoc(source, label)),
  }));
  const order = nav.flatMap(g => g.pages);
  const sources = new Set(['README.md', ...order.map(p => p.source)]);

  const guideSummaries = GUIDES.map(slug => {
    const {data} = frontMatter(fs.readFileSync(path.join(siteDir, 'pages', `${slug}.md`), 'utf8'));
    return {url: `/${slug}/`, label: data.label, description: data.description};
  });
  const rows = languageRows();
  const pages = [
    landing(sources),
    ...order.map(doc => docPage(doc, nav, order, sources)),
    ...GUIDES.map(slug => guidePage(slug, sources, guideSummaries)),
    guidePage('faq', sources, guideSummaries),
    ...[...rows.keys()].filter(slug => fs.existsSync(path.join(root, `docs/languages/${slug}.md`))).map(slug => languagePage(slug, rows, nav, sources)),
    schemaPage(),
    projectsPage(),
    brandPage(),
    notFound(),
  ];

  const context = {assets, guides: guideSummaries};
  for (const p of pages) {
    p.lastmod = lastmod(p.sources, buildTime);
    write(outDir, p.url, render(p, context));
    if (p.markdown) {
      write(outDir, `${p.url}index.md`, p.markdown);
    }
  }

  for (const [file, schema] of Object.entries(configSchemas())) {
    write(outDir, `/schema/${file}`, `${JSON.stringify(schema, null, 2)}\n`);
  }

  for (const file of fs.readdirSync(path.join(siteDir, 'schema'))) {
    copy(path.join(siteDir, 'schema', file), outDir, `schema/${file}`);
  }

  fs.writeFileSync(path.join(outDir, 'sitemap.xml'), sitemap(pages));
  fs.writeFileSync(path.join(outDir, 'robots.txt'), robots());
  fs.writeFileSync(path.join(outDir, 'llms.txt'), llms(pages));
  fs.writeFileSync(path.join(outDir, 'llms-full.txt'), llmsFull(pages));
  fs.writeFileSync(path.join(outDir, 'manifest.webmanifest'), manifest());
  fs.writeFileSync(path.join(outDir, '.nojekyll'), '');
  if (fs.existsSync(path.join(root, 'CNAME'))) {
    copy(path.join(root, 'CNAME'), outDir, 'CNAME');
  }

  return {outDir, pages: pages.filter(p => p.kind !== 'error').map(p => p.url)};
}

module.exports = {
  build, slugify, configSchemas, structuredData,
};

if (require.main === module) {
  const outArg = process.argv.indexOf('--out');
  build(outArg === -1 ? {} : {outDir: path.resolve(process.argv[outArg + 1])}).catch(error => {
    console.error(error);
    process.exitCode = 1;
  }).then(({outDir, pages}) => {
    console.log(`Built ${pages.length} pages into ${path.relative(process.cwd(), outDir) || '.'}`);
  });
}
