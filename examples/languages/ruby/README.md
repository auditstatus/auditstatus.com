# Ruby (Bundler; Puma, Sidekiq, Rails)

Deploy with git and `bundle config set deployment true` (gems in `vendor/bundle`). Bundler 2.6 and later write gem checksums into `Gemfile.lock` (`bundle lock --add-checksums`); without them each gem is compared with the checksum RubyGems.org publishes (`policy.unpinnedPackages`).

Checked: every gem file against the `.gem` from RubyGems.org, gemspecs (read without running Ruby), the wrappers RubyGems generates in the gem directory's `bin/` for each verified gem's executables, and each process for `RUBYOPT`, `RUBYLIB` and `-r debug/open`. `bundle exec` is accepted: exactly the `RUBYOPT` and `RUBYLIB` it sets are context, and the bundler gem they load is compared with the same version from RubyGems.org.

Gems with native extensions are compiled on the server; they are reported by `policy.builtPackages`.

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
