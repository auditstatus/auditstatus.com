# Ruby

Deploy a git checkout and install gems with Bundler in deployment mode, so they land in `vendor/bundle`. The attester hashes every file in the checkout and every installed gem, with its specification, compiled extensions and executable wrappers, and inspects each Ruby process. The verifier downloads the `.gem` whose SHA-256 `Gemfile.lock` pins, checks it, and compares its contents with the installed gem.


## What gets verified

| What                                                                     | Reference                                                                                                                 | Check               |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| Tracked files                                                            | The deployed commit, on the audited branch                                                                                | `source`            |
| Each gem's files                                                         | The `.gem` from RubyGems.org whose SHA-256 the `CHECKSUMS` section of `Gemfile.lock` pins                                 | `packages:rubygems` |
| Gems the lockfile has no checksum for                                    | The checksum RubyGems.org publishes for that version (`policy.unpinnedPackages`, default `warn`)                          | `packages:rubygems` |
| Gem specifications (Ruby code RubyGems loads at start-up)                | Must hold only literal values and agree with the gem's own metadata; read without running Ruby                            | `packages:rubygems` |
| Executable wrappers in `bin/` of the gem directory                       | The wrapper RubyGems generates for a verified gem's executable                                                            | `packages:rubygems` |
| RubyGems plugins                                                         | None allowed: RubyGems loads them into every Ruby process                                                                 | `packages:rubygems` |
| Each process                                                             | `RUBYOPT` and `-r`, `-I`, `-e` options, `RUBYLIB`, `RUBYGEMS_GEMDEPS`, `-r debug/open` and `RUBY_DEBUG_OPEN`, memory maps | `process`           |
| Bundler loaded by `bundle exec` (the bundler gem directory on `RUBYLIB`) | The `.gem` of that version from RubyGems.org, by the checksum RubyGems.org publishes                                      | `process`           |


## Requirements

* Commit `Gemfile.lock` (or `gems.locked`) with checksums. Bundler 2.6 and later write them: `bundle lock --add-checksums`.

* Install in deployment mode, so Bundler installs exactly the lockfile into `vendor/bundle`:

  ```sh
  bundle config set --local deployment true
  bundle install
  ```

* Ignore `vendor/` and `.bundle/` in `.gitignore`.

* `bundle exec` is supported. It sets `RUBYOPT` to require Bundler's setup (`-r<bundler lib>/bundler/setup`, or `-rbundler/setup` in older Bundler) and puts the installed bundler gem's `lib` directory on `RUBYLIB`. Exactly those values are accepted (`bundler-setup`, `bundler-rubylib`, info); the attester hashes that bundler gem's directory and the verifier compares it with the same version from RubyGems.org. With the Bundler that Ruby itself ships (Debian's and Ubuntu's `ruby` package), `bundle exec` leaves `RUBYLIB` empty and requires `bundler/setup` from the running interpreter's own library (`/usr/lib/ruby/3.2.0/bundler/setup` for `/usr/bin/ruby3.2`); that is accepted too (`bundler-setup`), as part of Ruby's standard library. Anything else in `RUBYOPT` or `RUBYLIB` still fails, so do not set them yourself. Starting without `bundle exec` works too (`require "bundler/setup"` in the app, as Rails does in `config/boot.rb`).

* Restart Puma and Sidekiq after each deploy. A tracked file changed after a process started fails (`policy.modifiedAfterStart`).


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /srv/app/current
    user: app
    ecosystems: [rubygems]
```

Gem directories are found at `vendor/bundle/ruby/<version>` and `.bundle/ruby/<version>` in the service root. For another `BUNDLE_PATH`, list the gem directory (the one holding `specifications/`):

```yaml
    installs:
      - ecosystem: rubygems
        dir: /srv/gems/ruby/3.3.0
```


## Verifier configuration

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
servers:
  - name: app1
    host: app1.example.com
```

Set `lockfiles.rubygems` when the lockfile is not at the repository root, and `references.registries.rubygems` for a mirror. See [configuration](../configuration.md).


## Build and deploy

The tested setup:

```sh
bundle lock --add-checksums               # in the repository, then commit Gemfile.lock
git clone https://github.com/example/app.git /srv/app/current
cd /srv/app/current
bundle config set --local deployment true
bundle install
```

Assets that Rails precompiles into `public/assets` are ignored files. Compare them with a build of the same commit by setting `build` in the verifier configuration; see [configuration](../configuration.md).


## Common findings

| Finding                                                                                     | Cause and fix                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RUBYOPT-require` and `RUBYLIB` (process)                                                   | `RUBYOPT` or `RUBYLIB` hold something other than exactly what `bundle exec` sets: another option or directory, or a Bundler that ships with Ruby (it sets no `RUBYLIB`). Remove the extra value, or install Bundler as a gem (`gem install bundler`). |
| `the Bundler directory on RUBYLIB (...) differs from bundler X on RubyGems.org` (process)   | The installed bundler gem was changed. Reinstall it (`gem install bundler -v X`).                                                                                                                                                                     |
| `Gemfile.lock has no checksums for these gems`                                              | Run `bundle lock --add-checksums` and commit the lockfile (`policy.unpinnedPackages`, default `warn`).                                                                                                                                                |
| `Gems with native extensions were compiled on the server`                                   | Their sources match; the compiled output has no reference (`policy.builtPackages`, default `warn`).                                                                                                                                                   |
| `installed gem is not in the lockfile`                                                      | The gem directory holds a gem the lockfile does not list. Clean it and install again.                                                                                                                                                                 |
| `installed from git (...); only gems from a gem server are compared`                        | A `git:` or `github:` gem. It cannot be checked (`policy.unverifiablePackages`, default `fail`). Publish it to a gem server.                                                                                                                          |
| `files differ from the gem`                                                                 | A gem was edited after install. Reinstall it.                                                                                                                                                                                                         |
| `its specification is not a generated literal specification`                                | A gemspec in `specifications/` was changed. Reinstall the gem.                                                                                                                                                                                        |
| `Files in bin/ that are not the wrapper RubyGems generates for a verified gem's executable` | A wrapper was edited or added. Reinstall.                                                                                                                                                                                                             |
| `RubyGems plugins are installed`                                                            | Remove the plugin, or the gem that installs it.                                                                                                                                                                                                       |


## Limits

* Native extensions are compiled on the server, so their output cannot be compared.
* Gems from git sources are not verified.
* With the Bundler that ships with Ruby as a default gem, `bundle exec` sets `RUBYOPT` to Ruby's own `bundler/setup` and no `RUBYLIB`; that is reported as `RUBYOPT-require`. Install Bundler as a gem, or start without `bundle exec`.
* The Ruby interpreter is explained as code only when a distribution package owns it or its hash is pinned under `executables`; see [the verifier guide](../verifier.md).

See [how it works](../how-it-works.md) for the overall flow.
