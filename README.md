# Bitcoin Handshake

This crate contains a library and binaries for demonstrating a network node handshake according to the [Bitcoin protocol](https://en.bitcoin.it/wiki/Protocol_documentation). 

## Handshake
The [specification](https://en.bitcoin.it/wiki/Version_Handshake) states that a full handshake consists of:
1. the connecting peer sending a Version message
2. the receiving peer responding with both a Version and Verack message 
3. the connecting peer sending its own Verack in response to the receiving peer's Version message

Both peers then continue communication using the lower of the two versions.

It is observed, however, that many implementations of the Bitcoin protocol seen in the wild frequently neglect to respond to Version messages with a Verack message, instead proceeding to send various message types such as Inv/Sendheaders. 

Therefore, if the `relax` CLI flag is present as a final argument then when Version messages have been exchanged and _our_ client has responded with a Verack, we'll count this is a successful handshake.

If `relax` is omitted, successful handshakes can still be witnessed, although at a rate of less than 5%.


## Run

### __seed_peers__

```rust
cargo run --bin seed_peers [relax]
```

The main binary makes parallel attempts to complete a handshake with all nodes in the result of `dig seed.bitcoin.sipa.be`, printing results to stdout.

## Testing

### __connect__

```rust
cargo run --bin connect 95.170.88.58:8333 [relax]
```
   
   Connect to a running node on the Mainnet (choose an address from `dig seed.bitcoin.sipa.be`) and terminate once a handshake has been successfully established, or failed. May need to run multiple times before seeing a success as remote peers routinely send invalid checksums. 
    
### __listen__

```rust
cargo run --bin listen [relax]
```

Listen for incoming peer connections (on port 8333) and attempt to establish a handshake with each, reporting successes/failures to stdout. The timeout for each peer to complete the handshake is set to 3 seconds. 
    
The listener may be tested with (multiple instances of) the `connect` example above, i.e. run the listener and then from a second terminal:

```rust
cargo run --bin connect 127.0.0.1:8333
```
