# Session key log

For debugging with test credentials, a build can export the keys it uses to
encrypt Matter messages, so that a packet capture can be decrypted offline (for
example with a Wireshark Matter dissector).

> **Warning:** exported keys are secret key material written in the clear. Only
> enable this in development builds that use test credentials.

## Enabling

The feature is compiled out by default. Build with the GN argument:

```
chip_enable_session_key_log = true
```

This requires the raw session keystore (the default for every crypto backend
except PSA); GN rejects the argument otherwise.

Linux example applications and chip-tool then accept:

```
--session-key-log <file>
```

Keys are appended to `<file>` as sessions are established. The file is never
truncated, so a controller and a device on the same host can share one file,
and keys from earlier runs remain available. Delete the file to start over.

The file is created with mode `0600`. To keep keys away from other users, an
existing file is refused if it is a symlink, is not a regular file, is owned
by another user, or is accessible by group or others.

Other applications can export keys by implementing
`chip::Crypto::SessionKeyLogDelegate` (`src/crypto/SessionKeyLog.h`) and
registering it with `chip::Crypto::SetSessionKeyLogDelegate()`, or by reusing
`chip::SessionKeyLogFile` from `examples/common/session-key-log`.

## File format

Line-based; blank lines and `#` comments are ignored.

```
PASE_KEY <session_id> <key>
CASE_KEY <session_id> <source_node_id> <key>
GROUP_EPOCH_KEY <compressed_fabric_id> <epoch_key>
```

-   `session_id`: 16-bit session ID from the message header (hex).
-   `source_node_id`: node ID of the sender that uses this key (hex). It is part
    of the nonce, but unicast message headers usually omit it.
-   `key`: 16-byte AES-CCM key (32 hex characters).
-   `compressed_fabric_id`: 8 bytes (16 hex characters).
-   `epoch_key`: 16-byte operational group epoch key (32 hex characters).

Each PASE or CASE session produces two lines, one per direction, each tagged
with the session ID its messages carry. `CASE_KEY` lines also carry the node ID
that sends with that key. `PASE_KEY` lines have no node ID: PASE messages always
use node ID 0 in the nonce.

## Scope

The log contains the keys of every session the node establishes and the group
keys of every fabric it belongs to. On a device commissioned into several
fabrics, that includes sessions with other administrators' controllers and
their fabrics' group keys, not only the traffic you are debugging.

## Limitations

-   Group epoch keys are exported only when a key set is written (for example by
    the Group Key Management cluster's `KeySetWrite` command). Key sets are
    stored as derived operational keys, so epoch keys written before the log was
    enabled cannot be exported later.
