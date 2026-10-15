# Nostr library API

All functions are local; callers provide Unix seconds. `Result<T>` is
`std::result::Result<T, Error>`; `Error::code(&self) -> &'static str` returns named
refusals. Secret keys have no formatting, serialization, cloning, or export API.
Every signature uses fresh auxiliary randomness. Fixed auxiliary randomness is
available only in unit tests.

```rust
impl SecretKey {
    pub fn generate() -> Result<Self>;
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self>;
    pub fn public_key(&self) -> [u8; 32];
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]>;
}
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()>;
pub fn npub_encode(public_key: &[u8; 32]) -> Result<String>;
pub fn npub_decode(npub: &str) -> Result<[u8; 32]>;
pub fn hex_encode(bytes: &[u8]) -> String;
pub fn hex_decode<const N: usize>(text: &str) -> Result<[u8; N]>;
```

`SecretKey`, `verify`, `npub_encode`, and `npub_decode` are reexported at the crate
root, and available in `keys` / `schnorr`. Secret input may be sealed by the
supervisor before passing it into `from_bytes`; the library never returns it.

```rust
// event module
pub const MAX_EVENT_BYTES: usize = 65_536;
pub struct Event {
    pub id: [u8; 32], pub pubkey: [u8; 32], pub created_at: u64, pub kind: u64,
    pub tags: Vec<Vec<String>>, pub content: String, pub sig: [u8; 64],
}
pub struct Rumor {
    pub id: [u8; 32], pub pubkey: [u8; 32], pub created_at: u64, pub kind: u64,
    pub tags: Vec<Vec<String>>, pub content: String,
}
impl Event {
    pub fn sign(key: &SecretKey, created_at: u64, kind: u64,
                tags: Vec<Vec<String>>, content: String) -> Result<Self>;
    pub fn verify(&self) -> Result<()>;
    pub fn parse(input: &[u8]) -> Result<Self>;
    pub fn to_json(&self) -> String;
}
impl Rumor {
    pub fn new(pubkey: [u8; 32], created_at: u64, kind: u64,
               tags: Vec<Vec<String>>, content: String) -> Result<Self>;
    pub fn verify(&self) -> Result<()>;
    pub fn parse(input: &[u8]) -> Result<Self>;
    pub fn to_json(&self) -> String;
}
pub fn event_id(pubkey: &[u8; 32], created_at: u64, kind: u64,
                tags: &[Vec<String>], content: &str) -> Result<[u8; 32]>;
pub fn serialize_for_id(pubkey: &[u8; 32], created_at: u64, kind: u64,
                        tags: &[Vec<String>], content: &str) -> Result<Vec<u8>>;
```

`Event::parse` authenticates its result. Public fields are mutable, so call
`verify` again if the event was modified. Event numbers are nonnegative integers
within JavaScript's safe integer range. Event ids use the NIP-01 encoder; the
existing `canon` parser supplies strict JSON parsing with duplicate rejection.

```rust
// nip44 module
pub const MAX_PLAINTEXT_BYTES: usize = 65_535;
pub fn get_conversation_key(secret: &SecretKey, public_key: &[u8; 32])
    -> Result<zeroize::Zeroizing<[u8; 32]>>;
pub fn calc_padded_len(unpadded_len: usize) -> Result<usize>;
pub fn encrypt(plaintext: &str, conversation_key: &[u8; 32]) -> Result<String>;
pub fn encrypt_with_nonce(plaintext: &str, conversation_key: &[u8; 32],
                          nonce: &[u8; 32]) -> Result<String>;
pub fn decrypt(payload: &str, conversation_key: &[u8; 32]) -> Result<String>;
```

`encrypt` generates the nonce. Callers of `encrypt_with_nonce` must never repeat
a nonce under a conversation key. Plaintext lengths are UTF-8 byte lengths.

```rust
// nip59 module
pub const SEAL_KIND: u64 = 13;
pub const GIFT_WRAP_KIND: u64 = 1059;
pub struct OpenedGift { pub rumor: Rumor, pub seal: Event }
pub fn seal(rumor: &Rumor, sender: &SecretKey, recipient: &[u8; 32], now: u64) -> Result<Event>;
pub fn wrap(seal: &Event, recipient: &[u8; 32], now: u64) -> Result<Event>;
pub fn gift_wrap(rumor: &Rumor, sender: &SecretKey, recipient: &[u8; 32], now: u64) -> Result<Event>;
pub fn unwrap(wrap: &Event, recipient: &SecretKey, now: u64) -> Result<OpenedGift>;
pub fn unwrap_seal(wrap: &Event, recipient: &SecretKey, now: u64) -> Result<Event>;
pub fn open_seal(seal: &Event, recipient: &SecretKey, now: u64) -> Result<Rumor>;
```

`wrap` generates a fresh one-time key; `seal` and `wrap` independently randomize
their timestamp within the previous two days. `unwrap` authenticates both signed
layers, rumor id, sender binding, recipient routing, and nonfuture timestamps.
`unwrap_seal` authenticates the wrap and seal without decrypting the rumor, so a
caller can refuse a sender by the seal's public key before reading the message.
`open_seal` reauthenticates the seal before decrypting and checking the rumor.
Neither helper treats the sender or plaintext as local authority.
