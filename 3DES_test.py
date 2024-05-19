# -*- coding: utf-8 -*-

# * TripleDES algorithm example

# ! ***EDUCATIONAL ONLY***
# ! THIS ALGORITHM AN THIS KIND OF USE IS ***DANGEROUS*** (THE ECB MODE MUST NOT BE USED)

from os import urandom
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import padding


# * In 3DES a 64 bits (8 bytes | 16 hex) key means a use of K1 = K2 = K3 (3DES-Single). This is a DES processing.
# * In 3DES a 128 bits (16 bytes | 32 hex) key means a use of K1 = K3 (3DES-Double).
# * In 3DES a 192 bits (24 bytes | 48 hex) key means a use of three different single keys (3DES-Triple).
key = urandom(16)

# ********* 3DES WITH ECB MODE *********

print("\n*** 3DES WITH ECB MODE ***\n")

# * Specify algorithm and operation mode
algorithm = TripleDES(key)
cipher = Cipher(algorithm, modes.ECB())


# * Input data
data = b"hola mundo"

print(f"Data without padding: {data.decode()}", 
      f"[Data length (bytes): {len(data)}]", sep='\n', end='\n\n')

# * Add padding to data for completing required data block size
# For 3DES-ECB data block size is 64 bits (8 bytes / 16 hex)
padder = padding.PKCS7(64).padder()
padded_data = padder.update(data) + padder.finalize()

print(f"Data with padding: {padded_data}", 
      f"[Data length (bytes): {len(padded_data)}]", sep='\n', end='\n\n')

# * Define the Cipher Context in "encryption direction/form"
encryptor = cipher.encryptor()
padded_cdata = encryptor.update(padded_data)    # "Charge" data on to "encryption" Cipher Context
padded_cdata += encryptor.finalize()            # When all data is treated, the Cipher Context must be finalized

print(f"Encrypted padded data: {padded_cdata}", 
      f"[Data length (bytes): {len(padded_cdata)}]", sep='\n', end='\n\n')


# * Define the Cipher Context in "decryption direction/form"
decryptor = cipher.decryptor() 
padded_pdata = decryptor.update(padded_cdata)    # "Charge" data on to "decryption" Cipher Context
padded_pdata += decryptor.finalize()             # When all data is treated, the Cipher Context must be finalized

print(f"Decrypted padded data: {padded_pdata}", 
      f"[Data length (bytes): {len(padded_pdata)}]", sep='\n', end='\n\n')

# * Remove the padding from decrypted data
unpadder = padding.PKCS7(64).unpadder()
pdata = unpadder.update(padded_pdata) + unpadder.finalize()

print(f"Decrypted data without padding: {pdata.decode()}", 
      f"[Data length (bytes): {len(pdata)}]", sep='\n', end='\n\n')