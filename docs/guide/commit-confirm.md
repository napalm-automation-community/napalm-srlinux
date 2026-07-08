# Commit confirm

A confirmed commit applies a change with a safety net: the device reverts it automatically unless you confirm within a time window. It is the standard guard against locking yourself out with a bad management-plane change.

```python
device.load_merge_candidate(config=risky_change)
device.commit_config(revert_in=120)   # applied, revert timer running

# verify you can still reach the device, run your checks ...

device.confirm_commit()               # keep the change, cancel the timer
```

If the session dies, your checks fail, or you simply do nothing - the device reverts the change by itself after 120 seconds.

## The API

`commit_config(revert_in=<seconds>)`
:   Applies the candidate and starts the revert timer. JSON candidates use the JSON-RPC `confirm-timeout` parameter; CLI candidates use `commit confirmed timeout <seconds>`.

`has_pending_commit()`
:   Returns `True` while a confirmed commit is awaiting confirmation. This is **device-side state** - it is visible to every session, including pending confirms started by other clients.

`confirm_commit()`
:   Accepts the pending commit and cancels the revert timer.

`rollback()`
:   Called while a confirm is pending, it **rejects** the pending commit immediately (`confirmed-reject`) instead of loading a checkpoint - the change is reverted right away rather than waiting for the timer.

A few rules the driver enforces:

- `commit_config()` refuses to run while another confirmed commit is pending.
- `revert_in` must be a positive number of seconds.
- `discard_config()` does **not** touch a pending confirm - it only clears a loaded-but-uncommitted candidate.

## Interaction with `commit_save`

With the [`commit_save`](connection.md#all-optional-arguments) optional argument, committed changes are also persisted to the startup configuration. For confirmed commits the `save startup` is **deferred until `confirm_commit()`** - the startup config never holds a change that may still auto-revert.

/// note | Minimum SR Linux version
Confirmed commits for JSON candidates rely on the JSON-RPC `confirm-timeout` parameter, available since SR Linux 23.3.2.
///

## A complete guarded change

```python
from napalm import get_network_driver

driver = get_network_driver("srlinux")
with driver("srl", "admin", "NokiaSrl1!",
            optional_args={"insecure": True, "commit_save": True}) as device:

    device.load_merge_candidate(config='set / system information location "lab"')
    print(device.compare_config())

    device.commit_config(revert_in=60)

    if checks_pass(device):          # your validation logic
        device.confirm_commit()      # change kept + saved to startup
    else:
        device.rollback()            # reject immediately, don't wait for the timer
```
