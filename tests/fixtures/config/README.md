# Test fixture: an estate-neutral `TRAUST_CONFIG_HOME`

`tests/conftest.py` copies this directory into a private config home and writes its
`traust.yaml` (locations under the test's temp trees), so the suite runs without any
operational configuration. The other files are its `model-registry.yaml` and a copy of a
shipped `config/*.example.*` template (renamed to its real filename).
Nothing here is deployment data and nothing here ships in the wheel. When a template changes
upstream, refresh the copy here.
