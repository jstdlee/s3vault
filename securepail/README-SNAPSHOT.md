# securePail snapshot

This folder is a snapshot (`git archive`) of the local `securePail` repository at commit `584c784`, a fork of [Pail](https://github.com/DejavuMoe/Pail). It is stored here only because the `jstdlee/securePail` repository did not exist when the work was done. Nothing in `s3vault` depends on it.

To move it into its own repository:

```
cd securepail && git init -b main && git add -A && git commit -m "securePail"
git remote add origin https://github.com/jstdlee/securePail && git push -u origin main
```

Status, evidence and open items: [PROGRESS.md](PROGRESS.md). The Swift CI scratch copy is `../securepail-ios/` with `../.github/workflows/securepail-ios.yml`.
