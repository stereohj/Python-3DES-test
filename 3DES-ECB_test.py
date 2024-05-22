# -*- coding: utf-8 -*-

# * TripleDES algorithm example with ECB Mode
# * By: stereohj (stereohj.dev@gmail.com)

# ! ***EDUCATIONAL ONLY***
# ! TDEA / Triple-DES / 3DES ALGORITHM AND THIS KIND OF USE IS ***DANGEROUS***

from os import urandom                                                      # Cryptographic secure PRNG (From Operating System)
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES     # Algorithm class
from cryptography.hazmat.primitives.ciphers import Cipher, modes            # Mode of operation class
from cryptography.hazmat.primitives import padding                          # Padding class


# * In 3DES a 64 bits (8 bytes | 16 hex) key means a use of K1 = K2 = K3 (3DES-Single). This is a DES processing.
# * In 3DES a 128 bits (16 bytes | 32 hex) key means a use of K1 = K3 (3DES-Double).
# * In 3DES a 192 bits (24 bytes | 48 hex) key means a use of three different single keys (3DES-Triple).
key = urandom(16)

print("\n*** 3DES WITH ECB MODE ***\n")

# * Specify algorithm and operation mode
algorithm = TripleDES(key)
cipher = Cipher(algorithm, modes.ECB())


# * Input data
data = b"messagesmessages"

print(f"Data: {data}", 
      f"[Data length (bytes): {len(data)}]", sep='\n', end='\n\n')


# * Data length must be multiple of 8 bytes / 64 bits. (3DES data block size)  
if len(data) % 8 != 0:

      # * Add padding to data for completing required data block size
      padder = padding.PKCS7(64).padder()
      padded_data = padder.update(data) + padder.finalize()

      print(f"PADDED Data: {padded_data}", 
            f"[Data length (bytes): {len(padded_data)}]", sep='\n', end='\n\n')
      
      data = padded_data
      
      is_padded = True

else:
      is_padded = False


# * Define the Cipher Context in "encryption direction/form"
encryptor = cipher.encryptor()
cdata = encryptor.update(data)      # "Charge" data on to "encryption" Cipher Context
cdata += encryptor.finalize()       # When all data is treated, the Cipher Context must be finalized

print(f"ENCRYPTED data: {cdata}", 
      f"[Data length (bytes): {len(cdata)}]", sep='\n', end='\n\n')


# * Define the Cipher Context in "decryption direction/form"
decryptor = cipher.decryptor() 
pdata = decryptor.update(cdata)     # "Charge" data on to "decryption" Cipher Context
pdata += decryptor.finalize()       # When all data is treated, the Cipher Context must be finalized


if is_padded:

      print(f"DECRYPTED PADDED data: {pdata}", 
            f"[Data length (bytes): {len(pdata)}]", sep='\n', end='\n\n')

      # * Remove the padding from decrypted data
      unpadder = padding.PKCS7(64).unpadder()
      pdata = unpadder.update(pdata) + unpadder.finalize()


print(f"DECRYPTED data: {pdata.decode()}", 
      f"[Data length (bytes): {len(pdata)}]", sep='\n', end='\n\n')