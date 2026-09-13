# Matter session key log

For debugging with test credentials, a build can export the session keys it
uses so that a packet capture can be decrypted offline (for example with the
Wireshark Matter dissector). This exposes secret key material in the clear and
must only be used with test credentials.

## Enabling

Set the `MATTER_KEYLOG` environment variable to a writable file path before
running a node (controller or device):

```
export MATTER_KEYLOG=/tmp/matter_keys.log
./chip-tool pairing onnetwork 1 20202021
```

Keys are appended as they are established. Logging is a no-op when the variable
is unset, and requires the raw key session keystore (the default); with an
opaque keystore (e.g. PSA) the exported bytes are not the usable key.

## File format

Line-based; blank lines and `#` comments are ignored.

```
CASE_KEY <session_id> <source_node_id> <key>
GROUP_EPOCH_KEY <compressed_fabric_id> <epoch_key>
```

- `session_id` — 16-bit session ID from the message header (hex).
- `source_node_id` — node ID of the sender that uses this key, for the nonce
  (hex); unicast headers usually omit it.
- `key` — 16-byte AES key (32 hex characters).
- `compressed_fabric_id` — 8 bytes (16 hex characters).
- `epoch_key` — 16-byte operational group epoch key (32 hex characters).

Each CASE/PASE session produces two `CASE_KEY` lines, one per direction, each
tagged with the session ID its messages carry and the node ID that sends with
that key.
