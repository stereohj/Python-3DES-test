# -*- coding: utf-8 -*-

# * TripleDES algorithm example with VARIANT method for key wrapping
# * By: stereohj (stereohj.dev@gmail.com)

# ! ***EDUCATIONAL ONLY***
# ! TDEA / Triple-DES / 3DES ALGORITHM is obsolete and ***SHOULD NOT BE USED***
# ! VARIANT method is obsolete and ***SHOULD NOT BE USED***

from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES     # Algorithm class
from cryptography.hazmat.primitives.ciphers import Cipher, modes            # Mode of operation class


# *** Key Check Digits function (3DES)
# * Encrypt a zeros data block with the key and take leftmost 3 bytes from the result
def key_check_digits(key: bytes) -> bytes:

      # ! ALERT: Algorithms classes can take keys an apply it some 
      # ! changes (e.g. most cryptographic systems needs 3DES keys
      # ! to be odd parity. So every rightmost bit -RSB- in a key
      # ! byte can be changed to "converit" in an odd parity byte).
      # ! For this reason USE the bytes *unmutable* object.
      # ! (DO NOT USE a bytearray *mutable* object).
      algorithm = TripleDES(key)      
      cipher = Cipher(algorithm, modes.ECB())

      zeros_data = bytes(len(key))  # key length must be 8 bytes / 16 hex / 64 bits multiple
      
      encryptor = cipher.encryptor()      
      kcv = encryptor.update(zeros_data)  # "Charge" "zeros_data" on to "encryption" Cipher Context  
      kcv += encryptor.finalize()         # When all data is treated, the Cipher Context must be finalized
      
      return kcv[0:3]


# *** To produce VARIANTS cryptograms:
# * 1)  Split the KEK/ZMK (Key Encryption Key / Zone Master Key) in two halves.
# * 2)  Take the most significant byte of each part and apply XOR 
# *     with the corresponding working key (WK) variant (byte).
# * 3)  Use the resulting key to encrypt the WK.


# Key Encryption Key (KEK): 3DES-Double key length (16 bytes / 32 hex / 128 bits)
KEK = '2ABC3DEF4567018998107645FED3CBA2'  # Hex notation
b_KEK = bytes.fromhex(KEK)                # Bytes object

# Key PIN Encryption (KPE): 3DES-Single key length (16 bytes / 32 hex / 128 bits)
KPE = '0123456789ABCDEFFEDCBA9876543210'  # Hex notation
b_KPE = bytes.fromhex(KPE)                # Bytes object

# KPE VARIANT 
VARIANT = '08'                            # KPE has the 08 Hex byte assigned (VARIANT 1)  
b_VARIANT = bytes.fromhex(VARIANT)        # Bytes object


# ** Left KEK "Variant" part

# * STEP 1: Get the index of the most significant byte (MS-byte)
lb_kek_index = 0                   

# * STEP 2:  Get the MS-byte and apply XOR with Variant byte
lb_var_kek = int.to_bytes( b_KEK[lb_kek_index] ^ int.from_bytes(b_VARIANT) )


# ** Right KEK "Variant" part

# * STEP 1: Get the index of the MS-byte
rb_kek_index = (len(b_KEK) // 2)

# * STEP 2:  Get the MS-byt and apply XOR with Variant byte
rb_var_kek = int.to_bytes( b_KEK[rb_kek_index] ^ int.from_bytes(b_VARIANT) )


# ** STEP 2: Get the Complete KEK "Variant"
b_KEK_VAR = lb_var_kek + b_KEK[1 : rb_kek_index] + rb_var_kek + b_KEK[rb_kek_index + 1 :]
KEK_VAR  = b_KEK_VAR.hex().upper()

hf_kek_index = len(KEK) // 2

print("\n*** 3DES VARIANT EXAMPLE ***\n")

print(f"VARIANT 1 (KPE - Hex notation): {VARIANT}\n")

print("KEK (Hex notation):\t\t", KEK[0 : 2], KEK[2 : hf_kek_index], 
      KEK[hf_kek_index : hf_kek_index + 2], KEK[hf_kek_index + 2: ], sep=' ')
print(f"KEK KCV (Hex notation): {key_check_digits(b_KEK).hex().upper()}\n")

print("KEK VARIANT (Hex notation):\t", KEK_VAR[0 : 2], KEK_VAR[2 : hf_kek_index], 
      KEK_VAR[hf_kek_index : hf_kek_index + 2], KEK_VAR[hf_kek_index + 2: ], sep=' ')

print(f"\nKPE (Hex notation): {b_KPE.hex().upper()}")
print(f"KPE KCV (Hex notation): {key_check_digits(b_KPE).hex().upper()}\n")


# ** STEP 3: Encrypt the KPE under KEK VARIANT

# * Specify algorithm and operation mode
algorithm = TripleDES(b_KEK_VAR)
cipher = Cipher(algorithm, modes.ECB())

# * Define the Cipher Context in "encryption direction/form"
encryptor = cipher.encryptor()
c_kpe = encryptor.update(b_KPE)     # "Charge" KPE on to "encryption" Cipher Context
c_kpe += encryptor.finalize()       # When all KPE is treated, the Cipher Context must be finalized

print(f"ENCRYPTED KPE by KEK VARIANT (Hex notation): {c_kpe.hex().upper()}\n")