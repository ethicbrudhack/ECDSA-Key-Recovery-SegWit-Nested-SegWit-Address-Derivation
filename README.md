# 🔐 ECDSA Key Recovery → SegWit & Nested SegWit Address Derivation

This script performs a **full ECDSA private key recovery and address verification**, reconstructing SegWit addresses (both Bech32 and nested P2SH) directly from recovered transaction data.  
It combines modular arithmetic for the key recovery step with Bitcoin address encoding logic.

---

## ⚙️ Step-by-step explanation

### 1️⃣ Recover the private key `d` from ECDSA signature data

Each ECDSA signature follows:

s ≡ k⁻¹ (z + r·d) (mod n)

Rearranged:


d ≡ (s·k − z) · r⁻¹ (mod n)


The script computes `d` from known values `(r, s, z, k)`:

```python
d = ((s * k - z) * inverse_mod(r, n)) % n
print(f"🚀 ✅ Obliczony klucz prywatny: {hex(d)}")


This yields the private key corresponding to the transaction signatures — the foundation for Bitcoin address generation.

2️⃣ Derive the public key from the recovered d
G = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1).verifying_key
pubkey = b'\x04' + G.to_string()  # Uncompressed public key (0x04 + X + Y)


The elliptic curve secp256k1 is used (Bitcoin’s curve).

The script creates an uncompressed public key (65 bytes).

3️⃣ Generate SegWit (Bech32) and Nested P2SH-P2WPKH addresses
🧩 Native SegWit (P2WPKH → starts with bc1)
HASH160(pubkey) = RIPEMD160(SHA256(pubkey))

h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
bech32_address = bech32.encode("bc", 0, h160)


This produces the modern Bech32 address format used in native SegWit transactions.

🧩 Nested SegWit (P2SH-P2WPKH → starts with 3)

To ensure backward compatibility with older wallets, the same key can be wrapped into a P2SH script:

nested_script = b'\x00\x14' + h160  # OP_0 + PUSH(20) + pubkey hash
nested_h160 = hashlib.new('ripemd160', hashlib.sha256(nested_script).digest()).digest()
nested_p2sh = base58.b58encode_check(b'\x05' + nested_h160).decode()


This yields a “3…” P2SH SegWit address.

4️⃣ Address verification

The recovered addresses are compared to an expected one:

if expected_address in [bech32_addr, nested_p2sh_addr]:
    print("✅ 🔥 Klucz prywatny jest poprawny dla SegWit!")
else:
    print("❌ Klucz prywatny NIE PASUJE do SegWit.")


This confirms whether the reconstructed key corresponds to the observed on-chain address.

📊 Example output
🚀 ✅ Obliczony klucz prywatny: 0x6a07dd14de5b...
🚀 ✅ Obliczony adres Bech32: bc1qyz...
🚀 ✅ Obliczony Nested SegWit P2SH-P2WPKH: 3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5
📌 🔹 Oczekiwany adres: 1612PT2zpMCMRwJsaR9YYs8YPgtYCPKrYe
✅ 🔥 Klucz prywatny jest poprawny dla SegWit!

🔢 Visual flow
ECDSA signature data: (r, s, z, k)
          ↓
Compute d = (s·k − z)·r⁻¹ mod n
          ↓
ECDSA public key (0x04 + X + Y)
          ↓
HASH160(pubkey)
     ↓             ↓
  Bech32 (bc1…)   P2SH (3…)
          ↓
Compare → expected address

🧠 Cryptographic insight

This demonstrates how leaked nonces (k) compromise ECDSA’s secrecy.

Once k is known, d can be computed algebraically — no brute force needed.

The script then reconstructs all modern Bitcoin address formats from d.

⚠️ Legal & ethical notice

This process should be used only for forensic research, academic demonstration, or auditing with explicit permission.
Recovering private keys from unauthorized transactions constitutes a violation of data and financial privacy laws.

© 2025 — Author: [ethicbrudhack]
BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
