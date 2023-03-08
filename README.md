# Bitcoin Handshake

This crate contains convenience types and functions for sending and receiving messages according to the [Bitcoin protocol](https://en.bitcoin.it/wiki/Protocol_documentation), and two example binaries which attempt to establish a protocol level handshake.

## Handshake
The [specification](https://en.bitcoin.it/wiki/Version_Handshake) states that a full handshake consists of:
1. the connecting peer sending a Version message
2. the receiving peer responding with both a Version and Verack message 
3. the connecting peer sending its own Verack 

Both peers then proceed to communicate using the lower of the two versions.

It is observed, however, that many implementations of the Bitcoin protocol seen in the wild frequently neglect to respond to Version messages with a Verack message, instead proceeding to send various message types such as Inv/Sendheaders. 

Therefore, if the `relax` CLI flag is present in the second argument position, then when Version messages have been exchanged and _our_ client has responded with a Verack, we'll count this is a successful handshake.

If `relax` is omitted, successful handshakes can still be witnessed, although at a rate of about 5%.

## Testing

### __connect__

```rust
cargo run --example connect 95.170.88.58:8333 [relax]
```
   
   Connect to a genuine running Bitcoin node on the Mainnet (choose an address from `dig seed.bitcoin.sipa.be`) and terminate once a handshake has been successfully established, or failed. May need to run multiple times before seeing a success as remote peers routinely send invalid checksums. 
    
### __listen__

```rust
cargo run --example listen [relax]
```

Listen for incoming peer connections (on port 8333) and attempt to establish a handshake with each, reporting successes/failures to stdout. The timeout for each peer to complete the handshake is set to 2 seconds. 
    
The listener may be tested with (multiple instances of) the `connect` example above, i.e. run the listener and then from a second terminal window:

```rust
cargo run --example connect 127.0.0.1:8333
```
    