# -*- coding: utf-8 -*-

# * TripleDES algorithm example with VARIANT method for key wrapping
# * By: stereohj (stereohj.dev@gmail.com)

# ! ***EDUCATIONAL ONLY***
# ! TDEA / Triple-DES / 3DES ALGORITHM is obsolete and ***SHOULD NOT BE USED***
# ! VARIANT method is obsolete and ***SHOULD NOT BE USED***

# * To produce variants:
# * 1)  Split the KEK/ZMK (Key Encryption Key / Zone Master Key) in two halves.
# * 2)  Take the most significant byte of each part and apply XOR 
# *     with the corresponding working key (WK) variant (byte).
# * 3)  Use the resulting key to encrypt the WK.


from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES     # Algorithm class
from cryptography.hazmat.primitives.ciphers import Cipher, modes            # Mode of operation class


# Key Encryption Key (KEK): 3DES-Double key length (16 bytes / 32 hex / 128 bits)
KEK = '2ABC3DEF4567018998107645FED3CBA2'    # Hex notation
b_KEK = bytearray.fromhex(KEK)              # Bytes *mutable* object

# Key PIN Encryption (KPE): 3DES-Single key length (8 bytes / 16 hex / 64 bits)
KPE = '0123456789ABCDEF'                    # Hex notation
b_KPE = bytearray.fromhex(KPE)              # Bytes *mutable* object

# KPE VARIANT
VARIANT_1 = '08'                            # Hex notation
b_VARIANT_1 = bytearray.fromhex(VARIANT_1)  # Bytes *mutable* object


# ** Left KEK "Variant" part

# * STEP 1: Get the index of the most significant byte (MS-byte)
lb_kek_index = 0                   

# * STEP 2:  Get the MS-byte and apply XOR with Variant byte
lb_var_kek = int.to_bytes( b_KEK[lb_kek_index] ^ int.from_bytes(b_VARIANT_1) )


# ** Right KEK "Variant" part

# * STEP 1: Get the index of the MS-byte
rb_kek_index = (len(b_KEK) // 2)

# * STEP 2:  Get the MS-byt and apply XOR with Variant byte
rb_var_kek = int.to_bytes( b_KEK[rb_kek_index] ^ int.from_bytes(b_VARIANT_1) )


# ** STEP 2: Get the Complete KEK "Variant 1"
b_KEK_VAR_1 = lb_var_kek + b_KEK[1 : rb_kek_index] + rb_var_kek + b_KEK[rb_kek_index + 1 :] 