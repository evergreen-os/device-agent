# Contributing

This repository is managed via Git. To push local changes to GitHub, ensure you have
an up-to-date checkout, commit your work, and run:

```bash
git push origin <branch-name>
```

If you are working within a restricted environment (such as this evaluation
sandbox), pushing directly to GitHub is not possible. Instead, export your patch
and apply it on a machine that has Git credentials configured before running
`git push`.
```
git format-patch origin/main
# copy the patch to a machine with access
```

