## What this changes

<!-- Describe the change and why it is needed. Link any related issue. -->

## Checklist

- [ ] The change does not touch playback, streaming, progress, image, or download paths
- [ ] Enforcement stays opt-in — nothing new turns on by default
- [ ] A plugin failure still fails open (never locks the administrator out)
- [ ] No secrets, tokens, real addresses, or server names are added anywhere
- [ ] `dotnet build -c Release` passes with 0 warnings
- [ ] `dotnet test -c Release` passes (add or update tests for behavior changes)
- [ ] Documentation updated if behavior or settings changed
