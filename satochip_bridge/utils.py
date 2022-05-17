# Source: https://github.com/spesmilo/electrum/blob/master/electrum/bip32.py
# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import hashlib
import hmac
import logging
from typing import List, Tuple, NamedTuple, Union, Iterable, Sequence, Optional

from pysatochip import ecc

# todo: add these methods in pysatochip

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
BIP32_PRIME = 0x80000000
UINT32_MAX = (1 << 32) - 1

def bh2u(x: bytes) -> str:
    """
    str with hex representation of a bytes-like object
    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return x.hex()

def rev_hex(s: str) -> str:
    return bh2u(bytes.fromhex(s)[::-1])
    
def int_to_hex(i: int, length: int=1) -> str:
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -(range_size//2) or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    if hasattr(hmac, 'digest'):
        # requires python 3.7+; faster
        return hmac.digest(key, msg, digest)
    else:
        return hmac.new(key, msg, digest).digest()

def protect_against_invalid_ecpoint(func):
    def func_wrapper(*args):
        child_index = args[-1]
        while True:
            is_prime = child_index & BIP32_PRIME
            try:
                return func(*args[:-1], child_index=child_index)
            except ecc.InvalidECPointException:
                _logger.warning('bip32 protect_against_invalid_ecpoint: skipping index')
                child_index += 1
                is_prime2 = child_index & BIP32_PRIME
                if is_prime != is_prime2: raise OverflowError()
    return func_wrapper


@protect_against_invalid_ecpoint
def CKD_pub(parent_pubkey: bytes, parent_chaincode: bytes, child_index: int) -> Tuple[bytes, bytes]:
    """Child public key derivation function (from public key only)
    This function allows us to find the nth public key, as long as n is
    not hardened. If n is hardened, we need the master private key to find it.
    """
    if child_index < 0: raise ValueError('the bip32 index needs to be non-negative')
    if child_index & BIP32_PRIME: raise Exception('not possible to derive hardened child from parent pubkey')
    return _CKD_pub(parent_pubkey=parent_pubkey,
                    parent_chaincode=parent_chaincode,
                    child_index=bytes.fromhex(rev_hex(int_to_hex(child_index, 4))))


# helper function, callable with arbitrary 'child_index' byte-string.
# i.e.: 'child_index' does not need to fit into 32 bits here! (c.f. trustedcoin billing)
def _CKD_pub(parent_pubkey: bytes, parent_chaincode: bytes, child_index: bytes) -> Tuple[bytes, bytes]:
    if len(parent_pubkey) !=33: raise ValueError('the bip32 parent pubkey must be in compresssed form') 
    I = hmac_oneshot(parent_chaincode, parent_pubkey + child_index, hashlib.sha512)
    pubkey = ecc.ECPrivkey(I[0:32]) + ecc.ECPubkey(parent_pubkey)
    if pubkey.is_at_infinity():
        raise ecc.InvalidECPointException()
    child_pubkey = pubkey.get_public_key_bytes(compressed=False)
    child_chaincode = I[32:]
    return child_pubkey, child_chaincode
   
def pubkey_to_ethereum_address(pubkey:bytes)-> str:
    """
    Get address from a public key
    """
    size= len(pubkey)
    if size<64 or size>65:
        addr= f"Unexpected pubkey size {size}, should be 64 or 65 bytes"
        return addr
        #raise Exception(f"Unexpected pubkey size{size}, should be 64 or 65 bytes")
    if size== 65:
        pubkey= pubkey[1:]

    pubkey_hash= keccak(pubkey)
    pubkey_hash= pubkey_hash[-20:]
    addr= "0x" + pubkey_hash.hex()
    return addr