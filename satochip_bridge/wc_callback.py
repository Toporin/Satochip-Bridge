import logging
import os
import rlp
from rlp.sedes import BigEndianInt, big_endian_int, Binary, binary, CountableList
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from ecdsa.curves import SECP256k1
from eth_hash.auto import keccak
from pykson import Pykson
from configparser import ConfigParser
from datetime import datetime

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

CURVE_ORDER = SECP256k1.order
MAX_INDEX = 1000 # should be same as eth-walletconnect-keyring constant

class WCCallback:

    def __init__(self, sato_client=None, sato_handler=None):
        self.wc_client= None # set on wallet_connect_initiate_session()
        self.sato_client= sato_client # manage a pysatochip CardConnector object, None by default as not  available during init, updated later
        self.sato_handler= sato_handler # manage UI
        self.wc_chain_id= 3 # Ropsten Ethereum by default # TODO: supports other chains?
        self.wc_bip32_path="" # default, to be updated

    def wallet_connect_initiate_session(self, wc_session: WCSession, chain_id: int, bip32_child=None, bip32_parent=None):
        logger.info(f"CALLBACK: wallet_connect_initiate_session WCSession={WCSession}")
        self.wc_session= wc_session
        #self.wc_bip32_path= bip32_path
        self.wc_chain_id= chain_id
        self.bip32_child= bip32_child
        self.bip32_parent= bip32_parent
        if bip32_child is not None:
            self.for_metamask= False
            self.wc_bip32_path= bip32_child["bip32_path"]
            self.wc_address= bip32_child["address"]
        if bip32_parent is not None:
            # when used for Metamask, the address and child bip32_path is defined on the Metmamask side during pairing
            self.for_metamask= True
            self.wc_bip32_path= None #bip32_parent["bip32_path"]
            self.wc_address= None
        # TODO: if both parent and child are None, we have an issue
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
            # url = remote_peer_meta.url
            # description = remote_peer_meta.description
            # icons = remote_peer_meta.icons
            if (name== "WalletConnect for Metamask"):
                # TODO: check url? + description?
                parent_pubkey= self.bip32_parent['pubkey']
                parent_chaincode= self.bip32_parent['chaincode']
                #child_pubkey= self.bip32_child['pubkey']
                bip32_path= self.bip32_parent['bip32_path']
                logger.info("accounts= " + str([parent_pubkey, parent_chaincode, bip32_path]))
                self.wc_client.approveSession([parent_pubkey, parent_chaincode, bip32_path], self.wc_chain_id)
            else:
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
        if wc_sign_type=="MESSAGE": # also called 'standard'
            address= raw[0]
            msg_raw= raw[1]
            msg_bytes= bytes.fromhex(msg_raw.strip("0x").strip("0X"))
        elif  wc_sign_type=="PERSONAL_MESSAGE":
            address= raw[1]
            msg_raw= raw[0] # yes, it's in the other order...
            msg_bytes= bytes.fromhex(msg_raw.strip("0x").strip("0X")) #TODO
        elif wc_sign_type=="TYPED_MESSAGE":
            #TODO!
            # https://eips.ethereum.org/EIPS/eip-712
            # https://github.com/MetaMask/eth-sig-util/commit/97caab50a98262b0ad01b21e1d0a52091b1bae5e
            address= raw[0]
            msg_raw= raw[1]
            msg_bytes= msg_raw.encode("utf-8") # not the correct specification!!
        # text decoding
        try:
            msg_txt= msg_bytes.decode('utf-8')
        except Exception as ex:
            msg_txt= str(msg_bytes)
        logger.info(f"CALLBACK: onEthSign - MESSAGE= {msg_txt}")
        logger.info(f"CALLBACK: onEthSign - msg_raw= {msg_raw}")
        msg_hash= self.msgtohash(msg_bytes)
        logger.info(f"CALLBACK: onEthSign - msg_hash= {msg_hash.hex()}")

        # check that from equals self.wc_address
        msg_address= address
        if (self.wc_address is not None) and (address != self.wc_address):
            msg_address=f"WARNING: request ({address}) does not correspond to the address managed by your Satochip ({self.wc_address}). In case of doubt, you should reject this request!"

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
            (event, values)= self.sato_client.request('wallet_connect_approve_action', "sign message", msg_address, msg_txt)
            if event== 'Yes':
                is_approved= True

        if is_approved:
            logger.info(f"CALLBACK Approve signature? YES!")
            try:
                # for Metamask, must recover bip32_path from address
                if (self.for_metamask):
                    bip32_path= self.get_path_from_address(address)
                else:
                    bip32_path= self.wc_bip32_path
                # derive key
                logger.debug(f"Derivation path= {bip32_path}")
                (pubkey, chaincode)= self.sato_client.cc.card_bip32_get_extendedkey(bip32_path)
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
            except Exception as ex:
                logger.warning(f"CALLBACK: exception in onEthSign: {ex}")
                self.wc_client.rejectRequest(id_)
        else:
            logger.info(f"CALLBACK Approve signature? NO!")
            self.wc_client.rejectRequest(id_)

    # todo: apply to every input
    def normalize(self, ins):
        ''' Normalize input
            For strings, remove any 'Ox' prefix, and ensure that number of chars is even
        '''
        if type(ins) is str:
            out= ins.replace("0x", "")
            if len(out)%2 == 1:
                out= "0" + out
            logger.info("in normalize: " +str(ins) +  " "  + str(out)) # debug tmp
            return out
        return ins

    def onEthSignTransaction(self, id_, param: WCEthereumTransaction):
        logger.info("CALLBACK: onEthSignTransaction")
        logger.info("CALLBACK: onEthSignTransaction param= " + str(param))
        logger.info(f"param.gas= {param.gas}")
        logger.info(f"param.gasLimit= {param.gasLimit}")
        logger.info(f"param.type_= {param.type_}")
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
            logger.warning(f"CALLBACK: exception in onEthSignTransaction: no gas value present")
            self.wc_client.rejectRequest(id_)
        if (param.chainId is not None):
            chainId= param.chainId
        else: # default
            chainId= self.wc_chain_id
        # from_= param.from_ #self.normalize(param.from_)
        # from_address= '0x'+from_
        # to= self.normalize(param.to)
        # nonce= self.normalize(param.nonce)
        # value= self.normalize(param.value)
        # data= self.normalize(param.data)
        # if (param.gas is not None):
            # gas= self.normalize(param.gas) # gas or gasLimit maybe  None
        # elif (param.gasLimit is not None):
            # gas= self.normalize(param.gasLimit)
        # else:
            # logger.warning(f"CALLBACK: exception in onEthSignTransaction: no gas value present")
            # self.wc_client.rejectRequest(id_)
        # if (param.chainId is not None):
            # chainId= param.chainId
        # else:
            # chainId= self.wc_chain_id

        # Legacy, EIP 1559
        type_= param.type_
        if (type_ is None or type_== 0): # legacy
            gasPrice= param.gasPrice
            tx_txt= f"Legacy transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nGas price: {gasPrice} \nData: {data} \nNonce: {nonce} \nChainId: {chainId}"
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

        elif type_==1: # eip2930
            gasPrice= param.gasPrice
            accessList = param.accessList # TODO
            logger.info(f"param.accessList= {param.accessList}")
            tx_txt= f"EIP2930 transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nGas price: {gasPrice} \nData: {data} \nNonce: {nonce} \nChainId: {chainId} \nAccessList: {accessList}"
            tx_bytes= [] # TODO!
            logger.warning(f"CALLBACK: exception in onEthSignTransaction: unsupported transaction type: {type_}")
            self.wc_client.rejectRequest(id_)

        elif type_==2: # eip1559
            maxPriorityFeePerGas= param.maxPriorityFeePerGas
            maxFeePerGas= param.maxFeePerGas
            accessList= param.accessList # TODO
            logger.info(f"param.accessList= {param.accessList}")
            tx_txt= f"EIP1559 transaction: \nTo: {to} \nValue: {value} \nGas: {gas} \nMaxFeePerGas: {maxFeePerGas} \nMaxPriorityFeePerGas: {maxPriorityFeePerGas} \nData: {data} \nNonce: {nonce} \nChainId: {chainId} \nAccessList: {accessList}"
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

        else:
            logger.warning(f"CALLBACK: exception in onEthSignTransaction: unsupported transaction type: {type_}")
            self.wc_client.rejectRequest(id_)

        # check that from equals self.wc_address
        if (self.wc_address is not None) and (from_ != self.wc_address):
            tx_txt+=f"\nWARNING: transaction 'From' value ({from_}) does not correspond to the address managed by your Satochip ({self.wc_address}). In case of doubt, you should reject this transaction!"

        logger.info(f"CALLBACK: onEthSignTransaction - tx_bytes= {tx_bytes.hex()}")
        tx_hash= keccak(tx_bytes)
        logger.info(f"CALLBACK: onEthSignTransaction - tx_hash= {tx_hash.hex()}")

        # request user approval
        is_approved= False
        hmac= None
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
        else:
            # request user approval via GUI
            (event, values)= self.sato_client.request('wallet_connect_approve_action', "sign transaction", from_, tx_txt)
            if event== 'Yes':
                is_approved= True

        if is_approved:
            logger.info(f"CALLBACK Approve tx signature? YES!")
            try:
                # for Metamask, must recover bip32_path from address
                if (self.for_metamask):
                    bip32_path= self.get_path_from_address(from_)
                else:
                    bip32_path= self.wc_bip32_path
                # derive key
                (pubkey, chaincode)= self.sato_client.cc.card_bip32_get_extendedkey(bip32_path)
                logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                # sign hash
                keynbr=0xFF
                (response, sw1, sw2)= self.sato_client.cc.card_sign_transaction_hash(keynbr, list(tx_hash), hmac)
                logger.info(f"CALLBACK: onEthSignTransaction - response= {response}")
                # parse sig
                (r,s,v, sigstring)= self.sato_client.cc.parser.parse_rsv_from_dersig(bytes(response), tx_hash, pubkey)
                logger.info(f"CALLBACK: onEthSignTransaction - r= {r}")
                logger.info(f"CALLBACK: onEthSignTransaction - s= {s}")
                logger.info(f"CALLBACK: onEthSignTransaction - v= {v}")
                logger.info(f"CALLBACK: onEthSignTransaction - sigstring= {sigstring.hex()}")
                sigstring= sigstring[1:]+sigstring[0:1] # for walletconnect, the v byte is appended AFTER r,s...
                logger.info(f"CALLBACK: onEthSignTransaction - sigstring= {sigstring.hex()}")
                sign_hex= "0x"+sigstring.hex()
                # for debug purpose: build signed tx
                # https://flightwallet.github.io/decode-eth-tx/
                # https://www.ethereumdecoder.com/
                # https://antoncoding.github.io/eth-tx-decoder/
                # tx_obj_signed= Transaction(
                                    # nonce= int(nonce, 16),
                                    # gas_price=int(gasPrice, 16),
                                    # gas= int(gas, 16),
                                    # to=bytes.fromhex(to),
                                    # value= int(value, 16),
                                    # data= bytes.fromhex(data),
                                    # v= v+35+2*chainId, #EIP155
                                    # r= r,
                                    # s= s,
                # )
                # tx_bytes_signed= rlp.encode(tx_obj_signed)
                # tx_raw_hex= "0x"+tx_bytes_signed.hex()
                # logger.info(f"CALLBACK: onEthSignTransaction - tx_raw_hex= {tx_raw_hex}")
                self.wc_client.approveRequest(id_, sign_hex)
            except Exception as ex:
                logger.warning(f"CALLBACK: exception in onEthSignTransaction: {ex}")
                self.wc_client.rejectRequest(id_)
        else:
            logger.info(f"CALLBACK Approve signature? NO!")
            self.wc_client.rejectRequest(id_)

    def onEthSendTransaction(self, id_, param: WCEthereumTransaction):
        logger.info(f"CALLBACK: onEthSendTransaction id={id_} - param={param}")
        self.wc_client.rejectRequest(id_) # currently unsupported


    def onEthSwitchChain(self, id_, param: WCEthereumSwitchChain):
        logger.info("CALLBACK: onEthSwitchChain")
        try:
            new_chain_id= int(param.chainId, 16)
            old_chain_id= self.wc_chain_id
            msg= f"Dapp requests to switch from {hex(old_chain_id)} to {hex(new_chain_id)}" # todo: display readable name
            (event, values)= self.sato_client.request('wallet_connect_approve_action', "switch chain", self.wc_address, msg)
            if event== 'Yes':
                self.wc_chain_id= new_chain_id
                self.wc_client.chainId= new_chain_id
                self.wc_client.approveRequest(id_, None) # https://docs.metamask.io/guide/rpc-api.html#wallet-switchethereumchain
            else:
                self.wc_client.rejectRequest(id_)
        except Exception as ex:
            logger.warning(f"CALLBACK: exception in onEthSwitchChain: {ex}")
            self.wc_client.rejectRequest(id_)

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

class TransactionUnsigned(rlp.Serializable):
    fields = [
        ("nonce", big_endian_int),
        ("gas_price", big_endian_int),
        ("gas", big_endian_int),
        ("to", Binary.fixed_length(20, allow_empty=True)),
        ("value", big_endian_int),
        ("data", binary),
    ]
