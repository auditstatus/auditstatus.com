# .NET (NuGet; ASP.NET Core)

Enable lock files (`RestorePackagesWithLockFile`) so `packages.lock.json` pins each package's content hash, and deploy the output of `dotnet publish`.

Checked: every package assembly in the publish directory against the package from nuget.org (its hash checked against the lock file), and each process for `DOTNET_STARTUP_HOOKS`, profiler variables (`CORECLR_ENABLE_PROFILING`) and diagnostic ports.

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
