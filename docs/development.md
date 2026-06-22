# Development

The project is managed with [uv](https://docs.astral.sh/uv/) — clone the repository and you're one command away from a working environment:

```bash
uv sync                  # create the venv and install all dependencies
uv run pytest test/unit  # unit tests (mocked JSON-RPC fixtures)
uv run ruff check napalm_srlinux test tools examples
```

## Unit tests

The unit tests run NAPALM's standard getter test framework against verbatim JSON-RPC responses recorded from a real lab — no device needed. The fixtures live under `test/unit/mocked_data/`, one directory per scenario.

```bash
uv run pytest test/unit
```

## Testing against a real node

The `test/ci` scripts exercise the driver end-to-end against a live SR Linux container in a [containerlab](https://containerlab.dev) topology:

```bash
make deploy-clab-ci      # single-node containerlab topology
make run-tests           # runs all test/ci scripts against it
make destroy-clab-ci
```

`SRL_VERSION` selects the SR Linux release for the topology (default: `latest`):

```bash
make deploy-clab-ci SRL_VERSION=25.10
```

CI runs the same scripts against multiple SR Linux releases on every pull request.

## Re-recording the unit-test fixtures

The mocked fixtures are recordings from a two-node lab with real protocol state (BGP, LLDP, ARP, mac-vrf, NTP, ...). When the driver's JSON-RPC requests change, re-record them:

```bash
make deploy-clab-record  # two-node recording topology
make record-fixtures     # configure the lab + record all fixtures
make destroy-clab-record
```

/// warning | Review before committing
Re-recorded fixtures are a snapshot of live device state. Review the resulting `git diff` carefully before committing — unrelated state changes (timestamps, counters) are expected, but structural changes deserve a close look.
///

## Documentation

This site is built with [Zensical](https://zensical.org). To work on the docs locally:

```bash
uv sync --group docs
uv run zensical serve    # live-reloading preview at http://localhost:8000
```

The site is published to GitHub Pages automatically when a release is published.

## Contributing

Contributions are welcome — the general [NAPALM contribution guidelines](https://napalm.readthedocs.io/en/latest/contributing/index.html) apply. Open an issue or pull request on [GitHub](https://github.com/napalm-automation-community/napalm-srlinux).
