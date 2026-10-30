# `tools/public-export/`: publishing a tree, not runtime config

Inputs to publishing a traust tree publicly. Nothing at run time reads them.

| File | What it is |
|---|---|
| `internal-vocabulary.example.yaml` | the template for your organization vocabulary: the rules naming your hosts, tools, trackers and products that the pre-publication scrub adds to its universal rules |

```bash
cp tools/public-export/internal-vocabulary.example.yaml ~/my-export/internal-vocabulary.yaml
$EDITOR ~/my-export/internal-vocabulary.yaml
traust admin scan-internal-refs --vocabulary ~/my-export/internal-vocabulary.yaml --fail-on review <repo>
```

`HARNESS_INTERNAL_VOCABULARY=<file>` does the same as `--vocabulary`, and also turns on the
estate-marker leg of `traust check docs-consistency`'s `config/` gate. Keep your copy out of
this tree: a vocabulary names what must not ship, so publishing it publishes the list.

The export itself (which repositories, which paths are stripped, how pins and links are
rewritten) is a deployment one-shot and lives with the deployment's own tooling, with its
`export.yaml`.
