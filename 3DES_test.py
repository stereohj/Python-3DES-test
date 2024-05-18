# TripleDES algorithm use example
# ***EDUCATIONAL ONLY***
# THIS ALGORITHM AN THIS KIND OF USE IS ***DANGEROUS*** (INCLUDING THE ECB MODE MUST NOT BE USED)

from os import urandom
from cryptography.hazmat.primitives.ciphers.algorithms  import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import padding


# Create the key (16 bytes / 32 hex / 128 bits)
# * A 128 bit key in 3DES means a use of k1 = k3.
key = urandom(16)


# Specify algorithm and operation mode
algorithm = TripleDES(key)
cipher = Cipher(algorithm, modes.ECB())


# Input data
data = b"abcd"

# Add padding to data for completing required data block size
# For 3DES-ECB data block size is 64 bits (8 bytes / 16 hex)
padder = padding.PKCS7(64).padder()
padded_data = padder.update(data) + padder.finalize()


# Define the Cipher Context in "encryption direction/form"
encryptor = cipher.encryptor()
padded_cdata = encryptor.update(padded_data)    # "Charge" data on to "encryption" Cipher Context
padded_cdata += encryptor.finalize()            # When all data is treated, the Cipher Context must be finalized


# Define the Cipher Context in "decryption direction/form"
decryptor = cipher.decryptor() 
padded_pdata = decryptor.update(padded_cdata)    # "Charge" data on to "decryption" Cipher Context
padded_pdata += decryptor.finalize()             # When all data is treated, the Cipher Context must be finalized

# Remove the padded data
unpadder = padding.PKCS7(64).unpadder()
pdata = unpadder.update(padded_pdata) + unpadder.finalize()

print(pdata)