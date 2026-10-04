/**
 * Audit Status - reference sources for a verification run
 *
 * Everything the verifier compares evidence with, obtained by the verifier
 * itself and shared by all servers in a run:
 *
 *   git        public repositories (one clone each), and their commits
 *   builds     reproduced builds of deployed commits, per service
 *   release    Node.js releases and npm packages (Attestium release-verification)
 *   store      downloads and cached manifests for the other ecosystems
 *   trust      Sigstore's trust root (TUF), for attestations and provenance
 *   archives   the Debian or Ubuntu archive, per distribution release
 *   registry   container registries
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Attestium = require('attestium');
const GitReference = require('./git');
const {BuildReference} = require('./build');

const {
  ReleaseVerification, http, ecosystems, attestations, distro, oci, gitTrees,
} = Attestium;

class References {
  /**
   * @param {Object} options
   * @param {Object} options.config - normalized verifier configuration
   * @param {Object} [options.httpOptions]
   * @param {Object} [options.buildOptions] - passed to BuildReference (env, log)
   * @param {Object} [options.env=process.env] - tokens
   * @param {Object} [options.trust] - a SigstoreTrust (tests)
   * @param {boolean} [options.allowFileUrls=false] - git over file:// (tests)
   * @param {Object} [options.confidential] - vendor roots for confidential VM reports ({roots, root}; tests)
   */
  constructor({config, httpOptions = {}, buildOptions = {}, env = process.env, trust, allowFileUrls = false, confidential = {}}) {
    this.confidential = confidential;
    this.config = config;
    this.httpOptions = httpOptions;
    this.buildOptions = buildOptions;
    this.env = env;
    const {cacheDir} = config.references;
    this.release = new ReleaseVerification({
      nodeDistUrl: config.references.nodeDistUrl,
      registryUrl: config.references.registryUrl,
      githubArchiveUrl: config.references.githubArchiveUrl,
      nodeKeyring: config.references.nodeKeyring,
      cacheDir: path.join(cacheDir, 'manifests'),
      ...httpOptions,
    });
    this.store = new ecosystems.ReferenceStore({
      cacheDir: path.join(cacheDir, 'ecosystems'),
      httpOptions,
      urls: config.references.registries,
    });
    this.gitTrees = new gitTrees.GitTrees({cacheDir: path.join(cacheDir, 'package-repos'), allowFileUrls});
    const trustedRoot = config.references.sigstore.trustedRoot ? JSON.parse(fs.readFileSync(config.references.sigstore.trustedRoot, 'utf8')) : undefined;
    this.trust = trust || new attestations.SigstoreTrust({
      cacheDir, httpOptions, tufUrl: config.references.sigstore.tufUrl, trustedRoot,
    });
    const endpoints = {};
    const credentials = {};
    for (const [name, registry] of Object.entries(config.references.containerRegistries)) {
      if (registry.url) {
        endpoints[name] = registry.url;
      }

      if (registry.tokenEnv && env[registry.tokenEnv]) {
        credentials[name] = {token: env[registry.tokenEnv]};
      }
    }

    this.registry = new oci.Registry({httpOptions, endpoints, credentials});
    this._git = new Map();
    this._builds = new Map();
    this._archives = new Map();
    this._auditorChecksums = new Map();
    this._images = new Map();
    this._versions = new Map();
  }

  /**
   * The commit a repository's servers must run (repository.version), or
   * null when any commit of the branch will do.  Resolved once per run.
   * `since` is when a version that moves became current: the release's
   * publication (GitHub's clock), or the branch tip's commit time.
   * @param {Object} repository - normalized repository
   * @returns {Promise<{commit: string, label: string, since?: string}|null>}
   */
  expectedVersion(repository) {
    if (repository.version === 'any') {
      return Promise.resolve(null);
    }

    const key = `${repository.url}#${repository.branch}#${repository.version}`;
    if (!this._versions.has(key)) {
      const promise = this._resolveVersion(repository);
      promise.catch(() => {});
      this._versions.set(key, promise);
    }

    return this._versions.get(key);
  }

  async _resolveVersion(repository) {
    const git = this.git(repository);
    const {version} = repository;
    if (version === 'latest') {
      const commit = await git.head();
      return {commit, label: `the latest commit of ${repository.branch}`, since: (await git.commitInfo(commit)).committedAt};
    }

    if (/^[\da-f]{40}$/.test(version)) {
      await git.fetchCommit(version);
      return {commit: version, label: `the pinned commit ${version.slice(0, 12)}`};
    }

    if (version !== 'latest-release') {
      return {commit: await git.tagCommit(version), label: `tag ${version}`};
    }

    // The latest release (not a draft or prerelease) of the GitHub
    // repository, by its tag.
    const name = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/.exec(repository.webUrl || repository.url);
    if (!name) {
      throw new Error('latest-release needs a GitHub repository (repository.url, or repository.webUrl on GitHub)');
    }

    const options = this.githubHttpOptions();
    const body = await http.httpGet(`${this.config.references.githubApiUrl}/repos/${name[1]}/releases/latest`, {
      ...options, maxBytes: 4 * 1024 * 1024, headers: {...options.headers, accept: 'application/vnd.github+json'},
    });
    let release = {};
    try {
      release = JSON.parse(body.toString('utf8')) || {};
    } catch {}

    const tag = release.tag_name;
    if (typeof tag !== 'string' || !/^(?!-)(?!.*\.\.)[\w.+/-]{1,200}$/.test(tag)) {
      throw new Error(`GitHub's latest release of ${name[1]} has no usable tag`);
    }

    const published = typeof release.published_at === 'string' && !Number.isNaN(Date.parse(release.published_at)) ? release.published_at : undefined;
    return {commit: await git.tagCommit(tag), label: `the latest release, ${tag}`, since: published};
  }

  /**
   * The git reference for a repository (one clone per URL).
   * @param {{url: string, branch: string}} repository
   * @returns {GitReference}
   */
  git(repository) {
    const key = `${repository.url}#${repository.branch}`;
    if (!this._git.has(key)) {
      this._git.set(key, new GitReference({url: repository.url, branch: repository.branch, cacheDir: this.config.references.cacheDir}));
    }

    return this._git.get(key);
  }

  /**
   * The build reference of a service, or null when it has no build.
   * @param {Object} service - normalized service
   * @returns {BuildReference|null}
   */
  build(service) {
    if (!service.build || !service.repository) {
      return null;
    }

    if (!this._builds.has(service.name)) {
      this._builds.set(service.name, new BuildReference({
        build: service.build, git: this.git(service.repository), cacheDir: this.config.references.cacheDir, ...this.buildOptions,
      }));
    }

    return this._builds.get(service.name);
  }

  /**
   * The signed archive of a distribution release, or null when none is
   * known for it.
   * @param {{id: string, codename: string}|null} release
   * @param {string} arch
   * @returns {Object|null} ArchiveReference
   */
  archive(release, arch) {
    if (!this.config.references.distro.enabled || !release) {
      return null;
    }

    const archives = this.config.references.distro.archives || distro.defaultArchives(release, arch);
    if (archives.length === 0) {
      return null;
    }

    const key = JSON.stringify(archives);
    if (!this._archives.has(key)) {
      this._archives.set(key, new distro.ArchiveReference({archives, store: this.store}));
    }

    return this._archives.get(key);
  }

  /**
   * HTTP options for GitHub's API (a token raises the rate limit).
   */
  githubHttpOptions() {
    const token = this.env[this.config.references.githubTokenEnv];
    return token ? {...this.httpOptions, headers: {authorization: `Bearer ${token}`}} : this.httpOptions;
  }

  /**
   * SHA-256 checksums published for an Audit Status release.
   * @param {string} version
   * @returns {Promise<Set<string>>}
   */
  auditorChecksums(version) {
    return this.checksumList(this.config.references.auditorChecksumsUrl, version);
  }

  /**
   * The SHA-256 hashes of a checksum list (cached per run).
   * @param {string} template - URL; `{version}` is replaced by the version
   * @param {string} version - as the evidence reports it
   * @returns {Promise<Set<string>>}
   */
  checksumList(template, version) {
    if (!/^\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(version)) {
      return Promise.reject(new Error(`Invalid auditor version: ${String(version).slice(0, 40)}`));
    }

    const url = template.replaceAll('{version}', version);
    if (!this._auditorChecksums.has(url)) {
      this._auditorChecksums.set(url, http.httpGet(url, {...this.httpOptions, maxBytes: 1024 * 1024}).then(body => {
        const hashes = new Set();
        for (const line of body.toString('utf8').split('\n')) {
          const match = line.trim().match(/^([\da-f]{64})\s+\*?\S+$/);
          if (match) {
            hashes.add(match[1]);
          }
        }

        return hashes;
      }));
    }

    return this._auditorChecksums.get(url);
  }

  /**
   * A container image's platform manifest and files (cached per run).
   */
  image(reference, platform, withFiles) {
    const key = `${reference.registry}/${reference.repository}@${reference.digest}|${platform.os}/${platform.architecture}|${withFiles}`;
    if (!this._images.has(key)) {
      this._images.set(key, (async () => {
        const resolved = await this.registry.platformManifest(reference, platform);
        const files = withFiles ? await oci.imageFiles(this.registry, reference, resolved.manifest) : null;
        return {...resolved, files};
      })());
      this._images.get(key).catch(() => this._images.delete(key));
    }

    return this._images.get(key);
  }
}

module.exports = {References};
