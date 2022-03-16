import logging
import os
import rlp
from rlp.sedes import big_endian_int, Binary, binary
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

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CURVE_ORDER = SECP256k1.order

class WCCallback:
    
    def __init__(self, sato_client=None, sato_handler=None):
        self.wc_client= None # set on wallet_connect_initiate_session()
        self.sato_client= sato_client # manage a pysatochip CardConnector object, None by default as not  available during init, updated later
        self.sato_handler= sato_handler # manage UI
        self.wc_chain_id= 1 # Ethereum by default # TODO: supports other chains?
        self.wc_bip32_path="" # default, to be updated
    
    def wallet_connect_initiate_session(self, wc_session: WCSession, bip32_path: str):
        logger.info(f"CALLBACK: wallet_connect_initiate_session WCSession={WCSession} - bip32_path={bip32_path}")
        self.wc_session= wc_session
        # get address corresponding to bip32_path 
        self.wc_bip32_path= bip32_path
        try:
            (self.wc_pubkey, self.wc_chaincode)= self.sato_client.cc.card_bip32_get_extendedkey(bip32_path)
        except Exception as ex:
            logger.warning(f"CALLBACK: exception in wallet_connect_initiate_session: {ex}")
            return
        self.wc_address= self.pubkey_to_ethereum_address(self.wc_pubkey.get_public_key_bytes(compressed=False))
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
        # request user approval
        # request_msg= ("An app wants to perform the following on your Satochip via WalletConnect:"+
                                            # "\n\tAction: sign message" +
                                            # "\n\tAddress: "+ str(self.wc_address)+
                                            # "\n\tMessage: "+ msg_txt+
                                            # "\n\nApprove action?")
        # (event, values)= self.sato_client.request('approve_action', request_msg)
        (event, values)= self.sato_client.request('wallet_connect_approve_action', "sign message", self.wc_address, msg_txt)
        if event== 'Yes':
            logger.info(f"CALLBACK Approve signature? YES!")
            try:
                # derive key
                (pubkey, chaincode)= self.sato_client.cc.card_bip32_get_extendedkey(self.wc_bip32_path)
                logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                #sign msg hash
                msg_hash= self.msgtohash(msg_bytes)
                logger.info(f"CALLBACK: onEthSign - msg_hash= {msg_hash.hex()}")
                keynbr=0xFF
                hmac= None
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
        
    def onEthSignTransaction(self, id_, param: WCEthereumTransaction):
        logger.info("CALLBACK: onEthSignTransaction")
        # parse tx
        from_= param.from_
        to= param.to.strip("0x")
        data= param.data.strip("0x")
        gas= param.gas
        gasPrice= param.gasPrice
        value= param.value
        nonce= param.nonce
        tx_txt= f"To: 0x{to} \nValue: {value} \nGas: {gas} \nGas price: {gasPrice} \nData: 0x{data} \nNonce: {nonce}"
        #todo: check that from equals self.wc_address
        # request user approval
        # request_msg= ("An app wants to perform the following on your Satochip via WalletConnect:"+
                                            # "\n\tAction: sign transaction" +
                                            # tx_txt +
                                            # "\n\nApprove action?")
        # (event, values)= self.sato_client.request('approve_action', request_msg)
        (event, values)= self.sato_client.request('wallet_connect_approve_action', "sign transaction", self.wc_address, tx_txt)
        if event== 'Yes':
            tx_obj= Transaction( # EIP155
                                nonce= int(nonce, 16),
                                gas_price=int(gasPrice, 16), 
                                gas= int(gas, 16), 
                                to=bytes.fromhex(to),  
                                value= int(value, 16), 
                                data= bytes.fromhex(data),      
                                v= self.wc_chain_id,
                                r=0,
                                s=0,
            )
            tx_bytes= rlp.encode(tx_obj)
            logger.info(f"CALLBACK: onEthSignTransaction - tx_bytes= {tx_bytes.hex()}")
            tx_hash= keccak(tx_bytes)
            logger.info(f"CALLBACK: onEthSignTransaction - tx_hash= {tx_hash.hex()}")
            try:
                # derive key
                (pubkey, chaincode)= self.sato_client.cc.card_bip32_get_extendedkey(self.wc_bip32_path)
                logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                # sign hash
                keynbr=0xFF
                hmac= None
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
                # https://flightwallet.github.io/decode-eth-tx/
                # https://www.ethereumdecoder.com/
                # https://antoncoding.github.io/eth-tx-decoder/
                tx_obj_signed= Transaction(
                                    nonce= int(nonce, 16),
                                    gas_price=int(gasPrice, 16), 
                                    gas= int(gas, 16), 
                                    to=bytes.fromhex(to),  
                                    value= int(value, 16), 
                                    data= bytes.fromhex(data),   
                                    v= v+35+2*self.wc_chain_id, #EIP155
                                    r= r,
                                    s= s,
                )
                tx_bytes_signed= rlp.encode(tx_obj_signed)
                tx_raw_hex= "0x"+tx_bytes_signed.hex()
                logger.info(f"CALLBACK: onEthSignTransaction - tx_raw_hex= {tx_raw_hex}")
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

class TransactionUnsigned(rlp.Serializable):
    fields = [
        ("nonce", big_endian_int),
        ("gas_price", big_endian_int),
        ("gas", big_endian_int),
        ("to", Binary.fixed_length(20, allow_empty=True)),
        ("value", big_endian_int),
        ("data", binary),
    ]