# napalm-srlinux

Community [NAPALM](https://napalm.readthedocs.io) driver for the [Nokia SR Linux](https://learn.srlinux.dev) network OS, built on the **JSON-RPC** management interface; the only runtime dependencies are `napalm` and `httpx`.

**Documentation: <https://napalm.srlinux.dev>**

## Development

The project is managed with [uv](https://docs.astral.sh/uv/):

```bash
uv sync                  # create the venv and install all dependencies
uv run pytest test/unit  # unit tests (mocked JSON-RPC fixtures)
uv run ruff check napalm_srlinux test tools examples
```

### Testing against a real node

```bash
make deploy-clab-ci      # single-node containerlab topology
make run-tests           # runs all test/ci scripts against it
make destroy-clab-ci
```

### Re-recording the unit-test fixtures

The mocked-data fixtures under `test/unit/mocked_data/` are verbatim JSON-RPC responses recorded from a real two-node lab (BGP, LLDP, ARP, mac-vrf, NTP, ...):

```bash
make deploy-clab-record  # two-node recording topology
make record-fixtures     # configure the lab + record all fixtures
make destroy-clab-record
```

Review the resulting `git diff` before committing re-recorded fixtures.

## License

Apache 2.0 - see [LICENSE](LICENSE).
