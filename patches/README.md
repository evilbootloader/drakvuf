# Xen-source patches

This directory holds out-of-tree patches that get applied to `drakvuf/xen/`
inside `package/Dockerfile-xen` (`patch -p1` after `configure-xen.sh`).

It is **intentionally empty** at the moment — every prior patch was found to
break Win10 HVM guest boot in production (see MAP-1828 for the bisection log
and per-patch md5 evidence). Re-introducing any patch is gated on a real
Win10 HVM boot smoke test on a DRAKVUF host, ideally automated.

The directory itself is tracked (via this README) so that
`COPY patches /build-patches` in `Dockerfile-xen` succeeds even when no
patches are present.

## Adding a patch (after re-enabling)

1. Apply your edits to `xen/` locally.
2. `cd xen && git diff > /tmp/my-patch.diff` to extract.
3. `git checkout -- .` to revert the working tree (xen submodule SHA stays clean).
4. Add a header to the diff describing what / why, save as `patches/NNNN-name.patch`.
5. Verify it applies: `cd xen && patch --dry-run -p1 < ../patches/NNNN-name.patch`.
6. **Boot-test on Win10 HVM** before committing.
7. Commit + push memdump, then bump submodule SHA in `drakvuf-build` and push main.
