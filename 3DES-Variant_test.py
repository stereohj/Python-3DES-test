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

from os import urandom                                                      # Cryptographic secure PRNG (From Operating System)
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES     # Algorithm class
from cryptography.hazmat.primitives.ciphers import Cipher, modes            # Mode of operation class
from cryptography.hazmat.primitives import padding                          # Padding class