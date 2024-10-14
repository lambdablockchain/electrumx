# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

from collections import namedtuple
import re
from decimal import Decimal
from hashlib import sha256

from electrumx.lib import util
from electrumx.lib.hash import Base58, double_sha256,  hash_to_hex_str
from electrumx.lib.hash import HASHX_LEN
from electrumx.lib.script import ScriptPubKey
import electrumx.lib.tx as lib_tx
import electrumx.server.block_processor as block_proc
from electrumx.server import daemon
from electrumx.server.session import ElectrumX


Block = namedtuple("Block", "raw header transactions")


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin:
    '''Base class of coin hierarchy.'''

    SHORTNAME = "LMC"
    NET = "mainnet"
    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\\[[0-9a-fA-F:]+\\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    SESSIONCLS = ElectrumX
    DEFAULT_MAX_SEND = 10000000
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = block_proc.BlockProcessor
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    RPC_PORT = 9332
    GENESIS_HASH = ('00000000343953f1ed4881e476c9e120'
                    '6976bfcf2cc86872d28ff6df9d879d18')
    GENESIS_ACTIVATION = 0
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ['TX_COUNT', 'TX_COUNT_HEIGHT', 'TX_PER_BLOCK']
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower() and
                    coin.NET.lower() == net.lower()):
                coin_req_attrs = req_attrs.copy()
                missing = [attr for attr in coin_req_attrs
                           if not hasattr(coin, attr)]
                if missing:
                    raise CoinError('coin {} missing {} attributes'
                                    .format(name, missing))
                return coin
        raise CoinError('unknown coin {} and network {} combination'
                        .format(name, net))

    @classmethod
    def sanitize_url(cls, url):
        # Remove surrounding ws and trailing /s
        url = url.strip().rstrip('/')
        match = cls.RPC_URL_REGEX.match(url)
        if not match:
            raise CoinError('invalid daemon URL: "{}"'.format(url))
        if match.groups()[1] is None:
            url += ':{:d}'.format(cls.RPC_PORT)
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        return url + '/'

    @classmethod
    def max_fetch_blocks(cls, height):
        if height < 13000:
            return 1
        return 1

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = block[:80]
        header_hex_hash = hash_to_hex_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))

        return header + bytes(1)

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script.'''
        return sha256(script).digest()[:HASHX_LEN]

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

    @classmethod
    def hash160_to_P2PKH_script(cls, hash160):
        return ScriptPubKey.P2PKH_script(hash160)

    @classmethod
    def hash160_to_P2PKH_hashX(cls, hash160):
        return cls.hashX_from_script(cls.hash160_to_P2PKH_script(hash160))

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a pubkey hash.

        Pass the address (either P2PKH or P2SH) in base58 form.
        '''
        raw = Base58.decode_check(address)

        # Require version byte(s) plus hash160.
        verbyte = -1
        verlen = len(raw) - 20
        if verlen > 0:
            verbyte, hash160 = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return cls.hash160_to_P2PKH_script(hash160)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash160)

        raise CoinError('invalid address: {}'.format(address))

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def block(cls, raw_block):
        '''Return a Block namedtuple given a raw block and its height.'''
        header = raw_block[:80]
        txs = cls.DESERIALIZER(raw_block, start=len(header)).read_tx_block()
        return Block(raw_block, header, txs)

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BSV is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN


class Lambda(Coin):
    NAME = "Lambda"
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 400
    PEERS = [
    ]
    GENESIS_ACTIVATION = 0
    RPC_PORT = 9332

class LambdaTestnetMixin:
    SHORTNAME = "XTN"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = (''
                    '')
    REORG_LIMIT = 8000
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 21
    RPC_PORT = 19332
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}

class LambdaTestnet(LambdaTestnetMixin, Coin):
    '''Lambda Testnet for Lambda daemons.'''
    GENESIS_HASH = ('')
    NAME = "LambdaTestnet"
    PEERS = [
    ]
    GENESIS_ACTIVATION = 0
    RPC_PORT = 19332 

class LambdaTestnet4(LambdaTestnetMixin, Coin):
    '''Lambda Testnet4 for Lambda daemons.'''
    GENESIS_HASH = ('')
    NAME = "LambdaTestnet4"
    PEERS = [
    ]
    GENESIS_ACTIVATION = 0
    RPC_PORT = 29332 
# 
class LambdaScalingTestnet(LambdaTestnet):
    NET = "scalingtest"
    GENESIS_HASH = ('')
    PEERS = [
    ]
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 1000
    TX_PER_BLOCK = 5000
    GENESIS_ACTIVATION = 0
    RPC_PORT = 39332 

    @classmethod
    def max_fetch_blocks(cls, height):
        if height <= 100:
            return 10
        return 3

class LambdaRegtest(LambdaTestnet):
    NET = "regtest"
    GENESIS_HASH = (''
                    '')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    GENESIS_ACTIVATION = 0
    RPC_PORT = 17443

class Lambda(Coin):
    NAME = "Lambda"
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 2000
    TX_PER_BLOCK = 10
    PEERS = [
    ]
    GENESIS_ACTIVATION = 0
