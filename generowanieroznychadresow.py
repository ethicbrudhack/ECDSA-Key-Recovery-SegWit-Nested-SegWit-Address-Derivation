from ecdsa.numbertheory import inverse_mod
from ecdsa.ecdsa import generator_secp256k1
import hashlib
import ecdsa
import base58
import bech32



# ✅ Twoje dane
r = int("d8e2d92d3fca2a3293ed2e57c80a8db40069da2229225756b77de2f967baa1fb", 16)
s = int("6f2dc5ce39475b4c98ae27285a36939aadf19e38b3845c57400ef08326d24d23", 16)
z = int("cc5260cf9f0c439f2847dae4560a63f62da6fb6682ed77df872076f0f0aafd34", 16)
k = int("1fc9ec4021b5c63a1f24f73c2554733dc0d684898670b3769a555f3cc2ae4968", 16)

# ✅ Stała wartość krzywej secp256k1 (order n)
n = generator_secp256k1.order()

# ✅ Obliczenie klucza prywatnego `d`
d = ((s * k - z) * inverse_mod(r, n)) % n
print(f"🚀 ✅ Obliczony klucz prywatny: {hex(d)}")

def private_key_to_segwit_addresses(d):
    """ Konwersja klucza prywatnego na adresy SegWit (P2WPKH i Nested P2SH-P2WPKH) """
    G = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1).verifying_key
    pubkey = b'\x04' + G.to_string()  # Klucz publiczny w formacie 04 + x + y

    # ✅ P2WPKH (bc1...)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    bech32_address = bech32.encode("bc", 0, h160)

    # ✅ Nested SegWit P2SH-P2WPKH (3...)
    nested_script = b'\x00\x14' + h160  # OP_0 + PUSH(20) + pubkey hash
    nested_h160 = hashlib.new('ripemd160', hashlib.sha256(nested_script).digest()).digest()
    nested_p2sh = base58.b58encode_check(b'\x05' + nested_h160).decode()

    return bech32_address, nested_p2sh

# ✅ Generujemy adresy SegWit
bech32_addr, nested_p2sh_addr = private_key_to_segwit_addresses(d)

expected_address = "1612PT2zpMCMRwJsaR9YYs8YPgtYCPKrYe"

print(f"🚀 ✅ Obliczony adres Bech32: {bech32_addr}")
print(f"🚀 ✅ Obliczony Nested SegWit P2SH-P2WPKH: {nested_p2sh_addr}")
print(f"📌 🔹 Oczekiwany adres: {expected_address}")

if expected_address in [bech32_addr, nested_p2sh_addr]:
    print("✅ 🔥 Klucz prywatny jest poprawny dla SegWit!")
else:
    print("❌ Klucz prywatny NIE PASUJE do SegWit.")
