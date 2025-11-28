# Terraform modules - pve-cloud-tf

Pve cloud terraform modules.

## Development

Read the tdd doc from the main ansible collection repository (pve_cloud).

Launch e2e tests:
```bash
pytest -s tests/e2e/ --skip-cleanup
```

## Regex for fast source code update

`(pve-cloud/pve-cloud-tf.git/.*?ref=)(.*)(")`

`$1NEW_VER$3` (vscode replace)
