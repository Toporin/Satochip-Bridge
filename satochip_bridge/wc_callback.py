import logging
import os
import rlp
import sys
import json
from os import path
from configparser import ConfigParser
from rlp.sedes import BigEndianInt, big_endian_int, Binary, binary, CountableList
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from ecdsa.curves import SECP256k1
from eth_hash.auto import keccak
from pykson import Pykson
from datetime import datetime
from py_eth_sig_utils import eip712
from py_eth_sig_utils import utils as eip712_utils

from pywalletconnectv1.wc_client import WCClient
from pywalletconnectv1.wc_session_store_item import WCSessionStoreItem
from pywalletconnectv1.models.wc_account import WCAccount
from pywalletconnectv1.models.wc_peer_meta import WCPeerMeta
from pywalletconnectv1.models.session.wc_session import WCSession
from pywalletconnectv1.models.ethereum.wc_ethereum_sign_message import WCEthereumSignMessage, WCSignType
from pywalletconnectv1.models.ethereum.wc_ethereum_transaction import WCEthereumTransaction
from pywalletconnectv1.models.ethereum.wc_ethereum_switch_chain import WCEthereumSwitchChain

try:
    from sato2FA import Sato2FA
    from utils import CKD_pub
except Exception as e:
    print('ImportError: '+repr(e))
    from satochip_bridge.sato2FA import Sato2FA
    from satochip_bridge.utils import CKD_pub

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

BIP32_PATH_LIST= ["m/44'/60'/0'/0/", "m/44'/1'/0'/0/", "m/"]
#CHAINID_LIST= ["0x1 - Ethereum", "0x3 - Ropsten", "0x38 - Binance Smart Chain"]
NETWORK_DICT= {0x1:"Ethereum", 0x3:"Ropsten", 0x38:"Binance Smart Chain"}
CHAINID_DICT= {v:k for k, v in NETWORK_DICT.items()}

CURVE_ORDER = SECP256k1.order
MAX_INDEX = 1000 # should be same as eth-walletconnect-keyring constant

class WCCallback:

    def __init__(self, sato_client=None, sato_handler=None):
        self.wc_client= None # set on wallet_connect_initiate_session()
        self.sato_client= sato_client # manage a pysatochip CardConnector object, None by default as not  available during init, updated later
        self.sato_handler= sato_handler # manage UI
        self.wc_chain_id= 1 # Ropsten Ethereum by default # TODO: supports other chains?
        self.wc_bip32_path="" # default, to be updated

    def wallet_connect_initiate_session(self, wc_session: WCSession, chain_id: int, bip32_child):
        logger.info(f"CALLBACK: wallet_connect_initiate_session WCSession={WCSession}")
        self.wc_session= wc_session
        self.wc_chain_id= chain_id
        self.bip32_child= bip32_child
        self.wc_bip32_path= bip32_child["bip32_path"]
        self.wc_address= bip32_child["address"]
        # set wc objects
        self.wc_client= WCClient()
        self.wc_client.set_callback(self)
        self.wc_peer_meta = WCPeerMeta(name = "Satochip-Bridge", url = "https://satochip.io", description="Satochip - the open-source and affordable hardware wallet!")
        # initiate connection
        self.wc_client.connect(wc_session, self.wc_peer_meta) # this will trigger method in wc_callback

    def onSessionRequest(self, id_, remote_peer_meta):
        logger.info(f"CALLBACK: onSessionRequest id_={id_} - remote_peer_meta={remote_peer_meta}")

        (event, values)= self.sato_client.request('wallet_connect_approve_new_session', remote_peer_meta)
        if event== 'Submit':
            logger.info("WalletConnection to Satochip approved!")

            name = remote_peer_meta.name
            self.wc_address= self.bip32_child['address']
            self.wc_client.approveSession([self.wc_address], self.wc_chain_id)
            self.wc_remote_peer_meta= remote_peer_meta
            self.sato_handler.show_notification("Notification","WalletConnection to Satochip approved by user!")
        else:
            logger.info("WalletConnection to Satochip rejected!")
            self.sato_handler.show_notification("Notification","WalletConnection to Satochip rejected by user!")
            self.wc_client.rejectSession()
            self.wc_client.disconnect()

    def killSession(self):
        logger.info("CALLBACK: killSession")
        if self.wc_session is not None:
            self.wc_client.killSession()
            self.wc_client= None
        else:
            self.wc_client.disconnect()

    def onFailure(self, ex):
        logger.info(f"CALLBACK: onFailure ex= {ex}")
        self.sato_client.request('show_error', f'Error while processing WalletConnect request: {ex}')

    def onEthSign(self, id_: int, wc_ethereum_sign_message: WCEthereumSignMessage):
        logger.info("CALLBACK: onEthSign")

        # parse msg
        raw= wc_ethereum_sign_message.raw
        wc_sign_type= wc_ethereum_sign_message.type_
        logger.info(f"CALLBACK: onEthSign - wc_sign_type= {wc_sign_type}")
        if wc_sign_type=="MESSAGE" or wc_sign_type=="PERSONAL_MESSAGE":
            if wc_sign_type=="MESSAGE": # also called 'standard'
                address= raw[0]
                msg_raw= raw[1]
            elif  wc_sign_type=="PERSONAL_MESSAGE":
                address= raw[1]
                msg_raw= raw[0] # yes, it's in the other order...
            msg_bytes= bytes.fromhex(self.normalize(msg_raw))
            msg_hash= self.msgtohash(msg_bytes)
            try:
                msg_txt= msg_bytes.decode('utf-8')
            except Exception as ex:
                msg_txt= str(msg_bytes)
        elif wc_sign_type=="TYPED_MESSAGE":
            # https://eips.ethereum.org/EIPS/eip-712
            # https://github.com/MetaMask/eth-sig-util/commit/97caab50a98262b0ad01b21e1d0a52091b1bae5e
            address= raw[0]
            msg_raw= raw[1]
            msg_txt= msg_raw
            try:
                json_data= json.loads(msg_raw)
                # check if domainSeparatorHex, hashStructMessageHex are present...
                if "typedData" in json_data:
                    typed_data= json_data["typedData"]
                else:
                    typed_data= json_data
                try:
                    logger.warning(f"CALLBACK: in onEthSign typed_data= {typed_data}")
                    msg_hash= eip712.encoding.encode_typed_data(typed_data)
                except Exception as ex:
                    # fallback: use domainSeparatorHex & hashStructMessageHex hashes for blind Signing
                    # This is NOT compliant with walletconnect specifications...
                    logger.warning(f"CALLBACK: exception in onEthSign while parsing typedData: {ex}")
                    domainSeparatorHex= json_data["domainSeparatorHex"]
                    hashStructMessageHex= json_data["hashStructMessageHex"]
                    msg_hash= eip712_utils.sha3(bytes.fromhex('19') +
                                                bytes.fromhex('01') +
                                                bytes.fromhex(domainSeparatorHex) +
                                                bytes.fromhex(hashStructMessageHex))
                    msg_txt= f"WARNING: could not parse typed_data (error: {ex}). \n\nBlind signing using msg_hash: {msg_hash.hex()}"
                    logger.warning(f"CALLBACK: blind signing using msg_hash: {msg_hash.hex()}")
            except Exception as ex:
                self.wc_client.rejectRequest(id_)
                msg_error= f"Request to sign typed message rejected! \n\nFailed to parse typedData with error: {ex}"
                logger.warning(f"CALLBACK: exception in onEthSign: {msg_error}")
                self.sato_handler.show_error(msg_error)
                return

        logger.info(f"CALLBACK: onEthSign - msg_raw= {msg_raw}")
        logger.info(f"CALLBACK: onEthSign - MESSAGE= {msg_txt}")
        logger.info(f"CALLBACK: onEthSign - msg_hash= {msg_hash.hex()}")

        # check that from equals self.wc_address
        if address != self.wc_address:
            self.wc_client.rejectRequest(id_)
            msg_error=f"Error: the request address ({address}) does not correspond to the address managed by WalletConnect ({self.wc_address}). \nThe request has been rejected! \n\nRequest: \n{msg_txt}"
            logger.warning(f"CALLBACK: error in onEthSign: {msg_error}")
            self.sato_handler.show_error(msg_error)
            return

        is_approved= False
        hmac= None
        if self.sato_client.cc.needs_2FA:
            # construct request msg for 2FA
            msg={}
            msg['action']= "sign_msg_hash"
            msg['alt']= "Ethereum"
            msg['msg']= msg_txt # msg_raw # in hex format
            msg['hash']= msg_hash.hex()
            (is_approved, hmac)= Sato2FA.do_challenge_response(self.sato_client, msg)
        else:
            # request user approval via GUI
            (event, values)= self.sato_client.request('wallet_connect_approve_action', "sign message", self.wc_address, self.wc_chain_id, msg_txt)
            if event== 'Yes':
                is_approved= True
                # todo: check selected network/chain_id?

        if is_approved:
            logger.info(f"CALLBACK Approve signature? YES!")
            try:
                # derive key
                logger.debug(f"Derivation path= {self.wc_bip32_path}")
                (pubkey, chaincode)= self.sato_client.cc.card_bip32_get_extendedkey(self.wc_bip32_path)
                logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                logger.debug(f"Address= {self.pubkey_to_ethereum_address(pubkey.get_public_key_bytes(compressed=False))}")
                #sign msg hash
                keynbr=0xFF
                (response, sw1, sw2)=self.sato_client.cc.card_sign_transaction_hash(keynbr, list(msg_hash), hmac)
                logger.info(f"CALLBACK: onEthSign - response= {response}")
                # parse sig
                (r,s,v, sigstring)= self.sato_client.cc.parser.parse_rsv_from_dersig(bytes(response), msg_hash, pubkey)
                logger.info(f"CALLBACK: onEthSign - r= {r}")
                logger.info(f"CALLBACK: onEthSign - s= {s}")
                logger.info(f"CALLBACK: onEthSign - v= {v}")
                logger.info(f"CALLBACK: onEthSign - sigstring= {sigstring.hex()}")
                sigstring= sigstring[1:]+ bytes([v+27])# for walletconnect, the v byte is appended AFTER r,s...
                logger.info(f"CALLBACK: onEthSign - sigstring= {sigstring.hex()}")
                sign_hex= "0x"+sigstring.hex()
                self.wc_client.approveRequest(id_, sign_hex)
                self.sato_handler.show_notification("Notification","Message signature request approved by user")
            except Exception as ex:
                self.wc_client.rejectRequest(id_)
                msg_error= f"Failed to sign message! \n\nError: {ex}"
                logger.warning(f"CALLBACK: exception in onEthSign: {msg_error}")
                self.sato_handler.show_error(msg_error)
        else:
            self.wc_client.rejectRequest(id_)
            logger.info(f"CALLBACK Approve signature? NO!")
            self.sato_handler.show_notification("Notification","Message signature request rejected by user")

    # todo: apply to every input
    def normalize(self, ins):
        ''' Normalize input
            For strings, remove any 'Ox' prefix, and ensure that number of chars is even
        '''
        if type(ins) is str:
            out= ins.replace("0x", "")
            if len(out)%2 == 1:
                out= "0" + out
            #logger.info("in normalize: " +str(ins) +  " "  + str(out)) # debug tmp
            return out
        return ins

    def onEthSignTransaction(self, id_, param: WCEthereumTransaction):
        logger.info("CALLBACK: onEthSignTransaction")
        self.processTransaction(id_, param, action='sign')

    def onEthSendTransaction(self, id_, param: WCEthereumTransaction):
        logger.info(f"CALLBACK: onEthSendTransaction id={id_} - param={param}")
        self.processTransaction(id_, param, action='send')

    def processTransaction(self, id_, param: WCEthereumTransaction, action: str):
        logger.info("CALLBACK: processTransaction")
        logger.info(f"CALLBACK: action= {action}")
        # parse tx
        from_= param.from_
        to= param.to
        nonce= param.nonce
        value= param.value
        data= param.data
        if (param.gas is not None):
            gas= param.gas # gas or gasLimit maybe  None
        elif (param.gasLimit is not None):
            gas= param.gasLimit
        else:
            self.wc_client.rejectRequest(id_)
            msg_error= f"Transaction request rejected! \n\nNo gas value present"
            logger.warning(f"CALLBACK: exception in processTransaction: no gas value present")
            self.sato_handler.show_error(msg_error)
            return
        if (param.chainId is not None):
            chainId= param.chainId
        else: # default
            chainId= self.wc_chain_id

        # check that from equals self.wc_address
        if from_ != self.wc_address:
            self.wc_client.rejectRequest(id_)
            msg_error=f"Error: the request address ({from_}) does not correspond to the address managed by WalletConnect ({self.wc_address}). \nThe request has been rejected! \n\nRequest: \n{tx_txt}"
            logger.warning(f"CALLBACK: error in processTransaction: {msg_error}")
            self.sato_handler.show_error(msg_error)
            return

        # Parse tx for display
        # Legacy, EIP 1559
        type_= param.type_
        if (type_ is None or type_== 0): # legacy
            gasPrice= param.gasPrice
            #tx_txt= f"Legacy transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nGas price: {gasPrice} \nData: {data} \nNonce: {nonce} \nChainId: {chainId}"
            tx_txt= f"Legacy transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nGas price: {gasPrice} \nData: {data} \nNonce: {nonce}"

        elif type_==1: # eip2930
            gasPrice= param.gasPrice
            accessList = param.accessList # TODO
            logger.info(f"param.accessList= {param.accessList}")
            #tx_txt= f"EIP2930 transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nGas price: {gasPrice} \nData: {data} \nNonce: {nonce} \nChainId: {chainId} \nAccessList: {accessList}"
            tx_txt= f"EIP2930 transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nGas price: {gasPrice} \nData: {data} \nNonce: {nonce} \nAccessList: {accessList}"
            tx_bytes= [] # TODO!
            self.wc_client.rejectRequest(id_)
            msg_error= f"Transaction request rejected! Error: unsupported transaction type: {type_}"
            logger.warning(f"CALLBACK: {msg_error}")
            self.sato_handler.show_error(msg_error)
            return

        elif type_==2: # eip1559
            maxPriorityFeePerGas= param.maxPriorityFeePerGas
            maxFeePerGas= param.maxFeePerGas
            accessList= param.accessList # TODO
            logger.info(f"param.accessList= {param.accessList}")
            #tx_txt= f"EIP1559 transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nMaxFeePerGas: {maxFeePerGas} \nMaxPriorityFeePerGas: {maxPriorityFeePerGas} \nData: {data} \nNonce: {nonce} \nChainId: {chainId} \nAccessList: {accessList}"
            tx_txt= f"EIP1559 transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nMaxFeePerGas: {maxFeePerGas} \nMaxPriorityFeePerGas: {maxPriorityFeePerGas} \nData: {data} \nNonce: {nonce} \nAccessList: {accessList}"

        else:
            self.wc_client.rejectRequest(id_)
            msg_error= f"Transaction request rejected! Error: unsupported transaction type: {type_}"
            logger.warning(f"CALLBACK: error in processTransaction: {msg_error}")
            self.sato_handler.show_error(msg_error)
            return

        # request user approval via GUI
        hmac= None
        if not self.sato_client.cc.needs_2FA: # skip this part if 2FA is enabled?
            (event, values)= self.sato_client.request('wallet_connect_approve_action', "sign transaction", from_, chainId, tx_txt)
            if event== 'Yes':
                # check chainId: if user changed the network, it will be reflected in the tx to sign
                new_network= values["network"]
                new_chainId= CHAINID_DICT[new_network]
                if (new_chainId != chainId):
                    logger.info(f"CALLBACK changed chainId from {hex(chainId)} to {hex(new_chainId)}")
                    chainId= new_chainId
                    # self.wc_chain_id= new_chainId # should we also update self.wc_chain_id?
            else:
                logger.info(f"CALLBACK Approve signature? NO!")
                self.wc_client.rejectRequest(id_)
                self.sato_handler.show_notification("Notification","Transaction request rejected by user")
                return

        # compute tx hash
        if (type_ is None or type_== 0): # legacy
            tx_obj= Transaction( # EIP155
                nonce= int(nonce, 16),
                gas_price=int(gasPrice, 16),
                gas= int(gas, 16),
                to=b'' if (to is None) else bytes.fromhex(self.normalize(to)),
                value= int(value, 16),
                data= bytes.fromhex(self.normalize(data)),
                v= chainId,
                r=0,
                s=0,
            )
            tx_bytes= rlp.encode(tx_obj)

        elif type_==2: # eip1559
            tx_obj= TransactionEIP1559(
                chain_id= chainId,
                nonce= int(nonce, 16),
                max_priority_fee_per_gas=int(maxPriorityFeePerGas, 16),
                max_fee_per_gas=int(maxFeePerGas, 16),
                gas= int(gas, 16),
                to= b'' if (to is None) else bytes.fromhex(self.normalize(to)),
                value= int(value, 16),
                data= bytes.fromhex(self.normalize(data)),
                access_list= accessList # TODO: parse accessList
            )
            tx_bytes= bytes([2]) + rlp.encode(tx_obj)

        tx_hash= keccak(tx_bytes)
        logger.info(f"CALLBACK: processTransaction - tx_bytes= {tx_bytes.hex()}")
        logger.info(f"CALLBACK: processTransaction - tx_hash= {tx_hash.hex()}")

        # 2FA approval if enabled
        if self.sato_client.cc.needs_2FA:
            # TODO
            # construct request msg for 2FA
            msg={}
            msg['action']= "sign_tx_hash"
            msg['tx']= tx_bytes.hex()
            msg['hash']= tx_hash.hex()
            msg['from']= from_ #self.wc_address TODO
            msg['chainId']= chainId # optionnal, otherwise taken from tx deserialization...
            (is_approved, hmac)= Sato2FA.do_challenge_response(self.sato_client, msg)
            if not is_approved:
                logger.info(f"CALLBACK Approve signature? NO!")
                self.wc_client.rejectRequest(id_)
                self.sato_handler.show_notification("Notification","Transaction request rejected by user via 2FA")
                return

        # Sign tx
        try:
            # derive key
            (pubkey, chaincode)= self.sato_client.cc.card_bip32_get_extendedkey(self.wc_bip32_path)
            logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
            # sign hash
            keynbr=0xFF
            (response, sw1, sw2)= self.sato_client.cc.card_sign_transaction_hash(keynbr, list(tx_hash), hmac)
            logger.info(f"CALLBACK: processTransaction - response= {response}")
            # parse sig
            (r,s,v, sigstring)= self.sato_client.cc.parser.parse_rsv_from_dersig(bytes(response), tx_hash, pubkey)
            logger.info(f"CALLBACK: processTransaction - r= {r}")
            logger.info(f"CALLBACK: processTransaction - s= {s}")
            logger.info(f"CALLBACK: processTransaction - v= {v}")
            logger.info(f"CALLBACK: processTransaction - sigstring= {sigstring.hex()}")
            sigstring= sigstring[1:]+sigstring[0:1] # for walletconnect, the v byte is appended AFTER r,s...
            logger.info(f"CALLBACK: processTransaction - sigstring= {sigstring.hex()}")
            sign_hex= "0x"+sigstring.hex()

            if (action == 'sign'):
                self.wc_client.approveRequest(id_, sign_hex)
                self.sato_handler.show_notification("Notification","Sign transaction request approved by user")
            elif (action == 'send'):
                # build signed tx for broadcast:
                # https://flightwallet.github.io/decode-eth-tx/
                # https://www.ethereumdecoder.com/
                # https://antoncoding.github.io/eth-tx-decoder/
                if (type_ is None or type_== 0): # legacy
                    tx_signed_obj= Transaction(
                            nonce= int(nonce, 16),
                            gas_price=int(gasPrice, 16),
                            gas= int(gas, 16),
                            to=b'' if (to is None) else bytes.fromhex(self.normalize(to)),
                            value= int(value, 16),
                            data= bytes.fromhex(self.normalize(data)),
                            v= v+35+2*chainId, #EIP155
                            r= r,
                            s= s,
                    )
                    tx_signed_bytes= rlp.encode(tx_signed_obj)
                elif type_==2: # eip1559
                    tx_signed_obj= TransactionEIP1559Signed(
                            chain_id= chainId,
                            nonce= int(nonce, 16),
                            max_priority_fee_per_gas=int(maxPriorityFeePerGas, 16),
                            max_fee_per_gas=int(maxFeePerGas, 16),
                            gas= int(gas, 16),
                            to= b'' if (to is None) else bytes.fromhex(self.normalize(to)),
                            value= int(value, 16),
                            data= bytes.fromhex(self.normalize(data)),
                            access_list= accessList, # TODO: parse accessList
                            y_parity= v,
                            r= r,
                            s= s,
                    )
                    tx_signed_bytes= bytes([2]) + rlp.encode(tx_signed_obj)

                tx_signed_hex= "0x"+tx_signed_bytes.hex()
                logger.info(f"CALLBACK: onEthSignTransaction - tx_raw_hex= {tx_signed_hex}")

                # broadcast tx and get tx_hash
                tx_signed_hash_hex= self.broadcastTransaction(chainId, tx_signed_hex)
                if tx_signed_hash_hex is None:
                    # TODO: show tx in error msg
                    self.wc_client.rejectRequest(id_)
                    msg_error=f"Failed to broadcast signed transaction! \n\nSigned tx:{tx_signed_hex}"
                    logger.warning(f"CALLBACK: error in processTransaction: {msg_error}")
                    self.sato_handler.show_error(msg_error)
                    return
                self.wc_client.approveRequest(id_, tx_signed_hash_hex)
                self.sato_handler.show_notification("Notification","Broadcast transaction request approved by user")
            else:
                # should not happen!
                self.wc_client.rejectRequest(id_)

        except Exception as ex:
            self.wc_client.rejectRequest(id_)
            logger.warning(f"CALLBACK: exception in processTransaction: {ex}")
            self.sato_handler.show_error(f'Failed to approve transaction! \n\nError:{ex}')

    def broadcastTransaction(self, chainId: int, tx_signed_hex: str):
        logger.debug("in broadcastTransaction")
        # get apikeys from file
        self.apikeys={}
        if getattr( sys, 'frozen', False ):
            # running in a bundle
            self.pkg_dir= sys._MEIPASS # for pyinstaller
        else :
            # running live
            self.pkg_dir = path.split(path.realpath(__file__))[0]
        apikeys_path= path.join(self.pkg_dir, "api_keys.ini")
        config = ConfigParser()
        if path.isfile(apikeys_path):
            config.read(apikeys_path)
            if config.has_section('APIKEYS'):
                self.apikeys= config['APIKEYS']
                #logger.debug('APIKEYS: '+ str(self.apikeys))

        # craft requests
        import requests
        if chainId== 0x1: # ethereum
            apikey= self.apikeys.get('API_KEY_ETHERSCAN','0')
            url= f"https://api.etherscan.io/api/?module=proxy&action=eth_sendRawTransaction&hex={tx_signed_hex}&apikey={apikey}"
        elif chainId== 0x3: # ropsten
            apikey= self.apikeys.get('API_KEY_ETHERSCAN','0')
            url= f"https://api-ropsten.etherscan.io/api/?module=proxy&action=eth_sendRawTransaction&hex={tx_signed_hex}&apikey={apikey}"
        elif chainId== 0x38: # bsc
            apikey= self.apikeys.get('API_KEY_BSCSCAN','0')
            url= f"https://api.bscscan.com/api/?module=proxy&action=eth_sendRawTransaction&hex={tx_signed_hex}&apikey={apikey}"
        elif chainId== 0x61: # bsc-test
            apikey= self.apikeys.get('API_KEY_BSCSCAN','0')
            url= f"https://api-testnet.bscscan.com/api/?module=proxy&action=eth_sendRawTransaction&hex={tx_signed_hex}&apikey={apikey}"
        else:
            logger.debug(f"in broadcastTransaction: unsupported chainId: {chainId}")
            return None

        # send requests and parse do_challenge_response
        logger.debug(f"in broadcastTransaction: url: {url}")
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'}
        response = requests.get(url, headers=headers)
        try:
            outputs = response.json()
            logger.debug(f"in broadcastTransaction: result: {outputs}")
            tx_signed_hash_hex= outputs['result'] # in str format
            return tx_signed_hash_hex
        except (ValueError, KeyError):
            logger.warning(f"in broadcastTransaction: unable to decode JSON from result: {response.text}")
            return None
        return None

    def onEthSwitchChain(self, id_, param: WCEthereumSwitchChain):
        logger.info("CALLBACK: onEthSwitchChain")
        try:
            new_chain_id= int(param.chainId, 16)
            old_chain_id= self.wc_chain_id
            #msg= f"Dapp requests to switch from {hex(old_chain_id)} to {hex(new_chain_id)}" # todo: display readable name
            msg= f"Dapp requests to switch from {NETWORK_DICT[old_chain_id]} to {NETWORK_DICT[new_chain_id]}" # todo: display readable name
            (event, values)= self.sato_client.request('wallet_connect_approve_action', "switch chain", self.wc_address, self.wc_chain_id, msg)
            if event== 'Yes':
                self.wc_chain_id= new_chain_id
                self.wc_client.chainId= new_chain_id
                self.wc_client.approveRequest(id_, None) # https://docs.metamask.io/guide/rpc-api.html#wallet-switchethereumchain
                self.sato_handler.show_notification("Notification","Switch chain request approved by user")
            else:
                self.wc_client.rejectRequest(id_)
                self.sato_handler.show_notification("Notification","Switch chain request rejected by user")
        except Exception as ex:
            self.wc_client.rejectRequest(id_)
            msg_error=f"Failed to switch chain! \n\nError:{ex}"
            logger.warning(f"CALLBACK: error in onEthSwitchChain: {msg_error}")
            self.sato_handler.show_error(msg_error)

    def onCustomRequest(self, id_, param):
        logger.info(f"CALLBACK: onCustomRequest id={id_} - param={param}")

    def onGetAccounts(self, id_):
        logger.info("CALLBACK: onGetAccounts")
        account = WCAccount(
            network= self.wc_chain_id,
            address= self.wc_address,
        )
        self.wc_client.approveRequest(id_, account)


    # UTILS #
    def pubkey_to_ethereum_address(self, pubkey:bytes)-> str:
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

    def msgtohash(self, msg_bytes: bytes) -> bytes:

        msg_length = str(len(msg_bytes)).encode('utf-8')
        msg_encoded= b'\x19Ethereum Signed Message:\n' + msg_length + msg_bytes
        msg_hash= keccak(msg_encoded)
        return msg_hash

    def txtohash(self, tx_json: str) -> bytes:
        tx_bytes= tx_json.encode('utf-8')
        tx_hash= keccak(tx_bytes)
        return tx_hash

    def get_path_from_address(self, address: str) -> str:
        """ returns the index corresponding to a given address, presumably BIP32 derived from chaincode and pubkey
        """
        logger.info(f"CALLBACK: get_index_from_address address={address}")
        address= address.lower()
        parent_bip32_path= self.bip32_parent['bip32_path']
        logger.info(f"CALLBACK: get_index_from_address parent_bip32_path={parent_bip32_path}")
        parent_chaincode_hex= self.bip32_parent['chaincode']
        parent_pubkey_hex=  self.bip32_parent['pubkey']
        parent_chaincode_bytes= bytes.fromhex(parent_chaincode_hex)
        parent_pubkey_bytes= bytes.fromhex(parent_pubkey_hex) # TODO: check: should be in compressed form
        for child_index in range(0, MAX_INDEX):
            logger.info(f"CALLBACK: get_index_from_address try index={child_index}")
            (child_pubkey_bytes, child_chaincode_bytes)= CKD_pub(parent_pubkey_bytes, parent_chaincode_bytes, child_index)
            child_address= self.pubkey_to_ethereum_address(child_pubkey_bytes)
            logger.info(f"CALLBACK: get_index_from_address try address={child_address}")
            if (child_address== address):
                logger.info(f"CALLBACK: get_index_from_address found index={child_index}")
                child_bip32_path= parent_bip32_path + str(child_index)
                logger.info(f"CALLBACK: get_index_from_address found path={child_bip32_path}")
                return child_bip32_path
        return ""

class Transaction(rlp.Serializable):
    fields = [
        ("nonce", big_endian_int),
        ("gas_price", big_endian_int),
        ("gas", big_endian_int),
        ("to", Binary.fixed_length(20, allow_empty=True)),
        ("value", big_endian_int),
        ("data", binary),
        ("v", big_endian_int),
        ("r", big_endian_int),
        ("s", big_endian_int),
    ]

# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md
# 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, signature_y_parity, signature_r, signature_s])
# https://github.com/ethereum/py-evm/blob/master/eth/vm/forks/london/transactions.py
class AccountAccesses(rlp.Serializable):
    fields = [
        ('account', Binary.fixed_length(20, allow_empty=True)),
        ('storage_keys', CountableList(BigEndianInt(32))),
    ]

class TransactionEIP1559(rlp.Serializable):
    fields = [
        ("chain_id", big_endian_int),
        ("nonce", big_endian_int),
        ("max_priority_fee_per_gas", big_endian_int),
        ("max_fee_per_gas", big_endian_int),
        ("gas", big_endian_int),
        ("to", Binary.fixed_length(20, allow_empty=True)),
        ("value", big_endian_int),
        ("data", binary),
        ("access_list", CountableList(AccountAccesses)),
    ]

class TransactionEIP1559Signed(rlp.Serializable):
    fields = [
        ('chain_id', big_endian_int),
        ('nonce', big_endian_int),
        ('max_priority_fee_per_gas', big_endian_int),
        ('max_fee_per_gas', big_endian_int),
        ('gas', big_endian_int),
        ('to', Binary.fixed_length(20, allow_empty=True)),
        ('value', big_endian_int),
        ('data', binary),
        ('access_list', CountableList(AccountAccesses)),
        ('y_parity', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]

class TransactionUnsigned(rlp.Serializable):
    fields = [
        ("nonce", big_endian_int),
        ("gas_price", big_endian_int),
        ("gas", big_endian_int),
        ("to", Binary.fixed_length(20, allow_empty=True)),
        ("value", big_endian_int),
        ("data", binary),
    ]
