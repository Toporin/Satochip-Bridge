import json
import threading
import time
import logging
import sys
import os.path
import rlp
from rlp.sedes import BigEndianInt, big_endian_int, Binary, binary, CountableList
from eth_hash.auto import keccak
from py_eth_sig_utils import eip712
from py_eth_sig_utils import utils as eip712_utils
#import traceback

from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

from pysatochip.CardConnector import CardConnector #, UninitializedSeedError
from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST

try:
    from Client import Client
    from handler import HandlerSimpleGUI
    from sato2FA import Sato2FA
except Exception as e:
    print('ImportError: '+repr(e))
    from satochip_bridge.Client import Client
    from satochip_bridge.handler import HandlerSimpleGUI
    from satochip_bridge.sato2FA import Sato2FA

if (len(sys.argv)>=2) and (sys.argv[1]in ['-v', '--verbose']):
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)

logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )

handler= HandlerSimpleGUI(logger.getEffectiveLevel())
client= Client(None, handler, logger.getEffectiveLevel())
cc = CardConnector(client, logger.getEffectiveLevel())
status= None
wallets = {}

EXIT_SUCCESS=0
EXIT_FAILURE=1

# TODO list:
# authentikey image
# Daemon mode
# logging & versioning
# DONE: Support 2FA
# DONE Check origin and host (+ whitelist?)
# DONE GUI
# DONE Satochip initialization

class SatochipBridge(WebSocket):

    def handleMessage(self):
        global cc, status, EXIT_SUCCESS, EXIT_FAILURE, logger
        logger.debug("In handleMessage()")
        logger.debug("Data: "+str(type(self.data))+"  "+self.data)

        # parse msg
        try:
            msg= json.loads(self.data)
            action= msg["action"]
        except Exception as e:
            logger.warning("exception: "+repr(e))
            cc.client.request('show_error', "Exception while parsing request: \n"+repr(e) )

        # check that card is present or wait
        while (cc.card_present is not True) or (cc.card_type != "Satochip"):
            (event, values)= cc.client.request('ok_or_cancel_msg','No card found! Please insert a Satochip to proceed...')
            if event== 'Ok' :
                continue
            else:
                # return failure code
                logger.debug("Cancel the request...")
                msg['exitstatus']=EXIT_FAILURE
                msg['reason']='No card found'
                reply= json.dumps(msg)
                self.sendMessage(reply)
                logger.debug("Reply (failure): "+reply)
                return

        try:
            if (action=="get_status"):
                response, sw1, sw2, status = cc.card_get_status()
                status["requestID"]= msg["requestID"]
                status["action"]= msg["action"]
                status['exitstatus']= EXIT_SUCCESS
                reply= json.dumps(status)
                self.sendMessage(reply)
                logger.debug("Reply: "+reply)

            elif (action=="get_chaincode"):
                path= msg["path"]
                #(depth, bytepath)= parser.bip32path2bytes(path)
                (pubkey, chaincode)= cc.card_bip32_get_extendedkey(path)
                # convert to string
                pubkey= pubkey.get_public_key_hex(False) # non-compressed hexstring
                chaincode= chaincode.hex() # hexstring
                d= {'requestID':msg["requestID"], 'action':msg["action"], 'pubkey':pubkey, 'chaincode':chaincode, 'exitstatus':EXIT_SUCCESS}
                reply= json.dumps(d)
                self.sendMessage(reply)
                logger.debug("Reply: "+reply)

            elif (action=="sign_tx_hash"):
                # only for EVM compatible blockchains
                path= msg["path"]
                # decode tx
                tx=  msg["tx"]
                tx_bytes= bytes.fromhex(tx)
                tx_dic=  msg["txDict"] # unused
                tx_chainid= msg.get("chainId", 3) # default to Ropsten
                try:
                    tx_from= '0x'+msg['from']
                except Exception as ex:
                    tx_from= '(not supported)'
                # parse eth tx type
                tx_firstbyte= tx_bytes[0]
                if 0xc0 <= tx_firstbyte <= 0xfe:
                    tx_type= 0
                    txrlp= rlp.decode(tx_bytes, Transaction)
                    tx_nonce= txrlp.nonce
                    tx_gas= txrlp.gas
                    tx_gas_price=txrlp.gas_price
                    tx_to='0x'+txrlp.to.hex()
                    tx_value= txrlp.value
                    tx_data='0x'+ txrlp.data.hex()
                    tx_chainid= msg.get('chainId',  txrlp.v)
                    # reencode with chainId (EIP155)
                    tx2= Transaction(txrlp.nonce, txrlp.gas_price, txrlp.gas, txrlp.to, txrlp.value, txrlp.data, tx_chainid, 0, 0)
                    tx2_raw= rlp.encode(tx2)
                    print("tx2_raw: " + tx2_raw.hex())
                    tx_hash = keccak(tx2_raw)
                    # for display
                    tx_txt= f"Legacy transaction: \nTo: {tx_to} \nValue: {tx_value} \nGas: {tx_gas} \nGas price: {tx_gas_price} \nData: {tx_data} \nNonce: {tx_nonce}"

                elif tx_firstbyte== 0x2:
                    tx_type= 0x2
                    try:
                        txrlp= rlp.decode(tx_bytes[1:], TransactionEIP1559Signed)
                    except Exception as ex:
                        txrlp= rlp.decode(tx_bytes[1:], TransactionEIP1559)
                    tx_nonce= txrlp.nonce
                    tx_gas= txrlp.gas
                    tx_to='0x'+txrlp.to.hex()
                    tx_value= txrlp.value
                    tx_data='0x'+ txrlp.data.hex()
                    tx_chainid= msg.get('chainId',  txrlp.chain_id)
                    tx_max_priority_fee_per_gas= txrlp.max_priority_fee_per_gas
                    tx_max_fee_per_gas= txrlp.max_fee_per_gas
                    tx_access_list= txrlp.access_list
                    # compute hash
                    tx_obj= TransactionEIP1559(
                                chain_id= tx_chainid,
                                nonce= txrlp.nonce,
                                max_priority_fee_per_gas= txrlp.max_priority_fee_per_gas,
                                max_fee_per_gas= txrlp.max_fee_per_gas,
                                gas= txrlp.gas,
                                to= txrlp.to,
                                value= txrlp.value,
                                data= txrlp.data,
                                access_list= txrlp.access_list
                            )
                    tx_bytes= bytes([2]) + rlp.encode(tx_obj)
                    tx_hash = keccak(tx_bytes)
                    # for displaye
                    tx_txt= f"EIP1559 transaction: \nTo: {tx_to} \nValue: {tx_value} \nGas: {tx_gas} \nMaxFeePerGas: {tx_max_fee_per_gas} \nMaxPriorityFeePerGas: {tx_max_priority_fee_per_gas} \nData: {tx_data} \nNonce: {tx_nonce} \nAccessList: {tx_access_list}"

                else:
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        'exitstatus':EXIT_FAILURE, 'reason':'unsupported transaction type'}
                    msg_error= f"Transaction request rejected! Error: unsupported transaction type: {tx_firstbyte}"
                    logger.warning(f"CALLBACK: error in processTransaction: {msg_error}")
                    cc.client.request('show_error', msg_error)
                    return

                logger.info(f"sign_tx_hash: - tx_bytes= {tx_bytes.hex()}")
                logger.info(f"sign_tx_hash - tx_hash= {tx_hash.hex()}")

                # TODO: get network info from chainlist https://github.com/ethereum-lists/chains

                # request user approval via GUI
                hmac= None
                is_approved= False
                (event, values)= cc.client.request('satochip_approve_action', "sign transaction", tx_from, tx_chainid, tx_txt)
                if event== 'Yes':
                    is_approved= True

                # 2FA approval if enabled
                if cc.needs_2FA:
                    is_approved= False
                    # construct request msg for 2FA
                    msg2FA={}
                    msg2FA['action']= "sign_tx_hash"
                    msg2FA['tx']= tx_bytes.hex()
                    msg2FA['hash']= tx_hash.hex()
                    msg2FA['from']= tx_from
                    msg2FA['chain']= "EVM"
                    msg2FA['chainId']= tx_chainid # optionnal, otherwise taken from tx deserialization...
                    (is_approved, hmac)= Sato2FA.do_challenge_response(client, msg2FA)

                if not is_approved:
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        'exitstatus':EXIT_FAILURE, 'reason':'request rejected by user'}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)
                    logger.info(f"CALLBACK Approve signature? NO!")
                    cc.client.request('show_notification', "Notification","Transaction request rejected by user")
                    return

                # Sign tx
                try:
                    # derive key
                    (pubkey, chaincode)= cc.card_bip32_get_extendedkey(path)
                    logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                    # sign hash
                    keynbr=0xFF
                    (response, sw1, sw2)= cc.card_sign_transaction_hash(keynbr, list(tx_hash), hmac)
                    logger.info(f"CALLBACK: processTransaction - response= {response}")
                    # parse sig
                    (r,s,v, sigstring)= cc.parser.parse_rsv_from_dersig(bytes(response), tx_hash, pubkey)
                    # r,s,v:int convert to hex (64-char padded with 0)
                    r= "{0:0{1}x}".format(r,64)
                    s= "{0:0{1}x}".format(s,64)
                    logger.info(f"CALLBACK: processTransaction - r= {r}")
                    logger.info(f"CALLBACK: processTransaction - s= {s}")
                    logger.info(f"CALLBACK: processTransaction - v= {v}")
                    logger.info(f"CALLBACK: processTransaction - sigstring= {sigstring.hex()}")
                    sigstring= sigstring[1:]+sigstring[0:1] # for walletconnect, the v byte is appended AFTER r,s...
                    logger.info(f"CALLBACK: processTransaction - sigstring= {sigstring.hex()}")
                    sign_hex= "0x"+sigstring.hex()
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        "sig":sign_hex, "r":r, "s":s, "v":v, "pubkey":pubkey.get_public_key_bytes().hex(),
                        'exitstatus':EXIT_SUCCESS}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)
                    cc.client.request('show_notification', "Notification","Sign transaction request approved by user")
                    return

                except Exception as ex:
                    logger.warning(f"Sign_tx_hash exception: {ex}")
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        'exitstatus':EXIT_FAILURE, 'reason':'exception during signature'}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)
                    cc.client.request('show_error', f'Failed to approve transaction! \n\nError:{ex}')
                    return

            elif (action=="sign_msg_hash"):
                # parse txt and hash
                chainId= 1 # default since personal message does not include chainId
                msg_raw= msg['msg']
                #hash= msg['hash'] # not used since hash is recomputed
                msg_bytes= bytes.fromhex(self.normalize(msg_raw))
                msg_hash= self.msgtohash(msg_bytes)
                try:
                    msg_txt= msg_bytes.decode('utf-8')
                except Exception as ex:
                    msg_txt= str(msg_bytes)

                # prepare key corresponding to desired path
                path= msg["path"]
                (pubkey, chaincode)= cc.card_bip32_get_extendedkey(path)
                address= self.pubkey_to_ethereum_address(pubkey.get_public_key_bytes(compressed=False))
                logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                logger.debug("Sign with address: " + address)

                is_approved= False
                hmac= None
                (event, values)= cc.client.request('satochip_approve_action', "sign message", address, chainId, msg_txt)
                if event== 'Yes':
                    is_approved= True

                if cc.needs_2FA:
                    is_approved= False
                    msg2FA={}
                    msg2FA['action']= "sign_msg_hash"
                    msg2FA['alt']= "Ethereum"
                    msg2FA['hash']= msg_hash.hex()
                    msg2FA['msg']= msg_raw # string in hex format for personal-message
                    msg2FA['msg_type']= 'PERSONAL_MESSAGE'
                    (is_approved, hmac)= Sato2FA.do_challenge_response(client, msg2FA)

                if not is_approved:
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        'exitstatus':EXIT_FAILURE, 'reason':'Signing request rejected by user'}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)
                    return
                else:
                    keynbr=0xFF
                    (response, sw1, sw2)=cc.card_sign_transaction_hash(keynbr, list(msg_hash), hmac)

                    # convert sig to rsv format:
                    logger.debug ("Convert sig to rsv format...")
                    try:
                        (r,s,v, sigstring)= cc.parser.parse_rsv_from_dersig(bytes(response), msg_hash, pubkey)
                        # r,s,v:int convert to hex (64-char padded with 0)
                        r= "{0:0{1}x}".format(r,64)
                        s= "{0:0{1}x}".format(s,64)
                        logger.debug("sigstring: " + sigstring.hex())
                        logger.debug ("r= " + r)
                        logger.debug ("s= " + s)
                        logger.debug ("v= " + str(v))
                    except Exception as e:
                        logger.warning("Exception in parse_rsv_from_dersig: " + repr(e))
                        cc.client.request('show_error', "Exception in parse_rsv_from_dersig: " + repr(e))
                        d= {'requestID':msg["requestID"], 'action':msg["action"],
                            'exitstatus':EXIT_FAILURE, 'reason':'Exception in parse_rsv_from_dersig'}
                        reply= json.dumps(d)
                        self.sendMessage(reply)
                        return
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        'sig':sigstring.hex(), "r":r, "s":s, "v":v, "pubkey":pubkey.get_public_key_bytes().hex(),
                        'exitstatus':EXIT_SUCCESS}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)
                    return

            elif (action=="sign_typed_data_hash"):
                # currently, only for ethereum-compatible VM
                # prepare key corresponding to desired path
                path= msg["path"]
                address= msg["address"]
                logger.debug("Sign with address: "+ address)

                typedData= msg["typedData"]
                domainSeparatorHex= msg["domainSeparatorHex"]
                hashStructMessageHex= msg["hashStructMessageHex"]
                # get chainId and ensure that chainId is an int
                chainId= int(typedData.get('domain').get('chainId', 3)) # ropsten by default for security
                typedData['domain']['chainId']= chainId
                try:
                    logger.warning(f"CALLBACK: in onEthSign typedData= {typedData}")
                    msg_hash= eip712.encoding.encode_typed_data(typedData)
                    msg_txt= json.dumps(typedData)
                except Exception as ex:
                    # fallback: use domainSeparatorHex & hashStructMessageHex hashes for blind Signing
                    logger.warning(f"CALLBACK: exception in onEthSign while parsing typedData: {ex}")
                    msg_hash= eip712_utils.sha3(bytes.fromhex('19') +
                                                bytes.fromhex('01') +
                                                bytes.fromhex(domainSeparatorHex) +
                                                bytes.fromhex(hashStructMessageHex))
                    msg_txt= f"WARNING: could not parse typedData (error: {ex}). \n\nBlind signing using msg_hash: {msg_hash.hex()}"
                    logger.warning(f"CALLBACK: blind signing using msg_hash: {msg_hash.hex()}")

                is_approved= False
                hmac= None
                (event, values)= client.request('satochip_approve_action', "sign message", address, chainId, msg_txt)
                if event== 'Yes':
                    is_approved= True

                if cc.needs_2FA:
                    is_approved= False
                    # construct request msg for 2FA
                    msg2FA={}
                    msg2FA['action']= "sign_msg_hash"
                    msg2FA['alt']= "Ethereum"
                    msg2FA['hash']= msg_hash.hex()
                    msg2FA['msg_type']= "TYPED_MESSAGE"
                    msg2FA['msg']= json.dumps({'typedData':typedData, 'domainSeparatorHex':domainSeparatorHex, 'hashStructMessageHex':hashStructMessageHex})# string in hex format for personal-message, or json-serialized for typed-message
                    (is_approved, hmac)= Sato2FA.do_challenge_response(client, msg2FA)

                if is_approved:
                    # derive key
                    logger.debug(f"Derivation path= {path}")
                    (pubkey, chaincode)= cc.card_bip32_get_extendedkey(path)
                    logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                    logger.debug(f"Address= {self.pubkey_to_ethereum_address(pubkey.get_public_key_bytes(compressed=False))}")
                    # todo: check addresses match!
                    #sign msg hash
                    keynbr=0xFF
                    (response, sw1, sw2)= cc.card_sign_transaction_hash(keynbr, list(msg_hash), hmac)
                    logger.info(f"CALLBACK: onEthSign - response= {response}")
                    # parse sig
                    (r,s,v, sigstring)= cc.parser.parse_rsv_from_dersig(bytes(response), msg_hash, pubkey)
                    # r,s,v:int convert to hex (64-char padded with 0)
                    r= "{0:0{1}x}".format(r,64)
                    s= "{0:0{1}x}".format(s,64)
                    logger.info(f"CALLBACK: onEthSign - r= {r}")
                    logger.info(f"CALLBACK: onEthSign - s= {s}")
                    logger.info(f"CALLBACK: onEthSign - v= {v}")
                    logger.info(f"CALLBACK: onEthSign - sigstring= {sigstring.hex()}")
                    #sigstring= sigstring[1:]+ bytes([v+27])# for walletconnect, the v byte is appended AFTER r,s...
                    sigstring= sigstring[1:]+ bytes([v])# for walletconnect, the v byte is appended AFTER r,s...
                    logger.info(f"CALLBACK: onEthSign - sigstring= {sigstring.hex()}")
                    sign_hex= "0x"+sigstring.hex()
                    #self.sato_handler.show_notification("Notification","Message signature request approved by user")
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        "sig":sign_hex, "r":r, "s":s, "v":v, "pubkey":pubkey.get_public_key_bytes().hex(),
                        'exitstatus':EXIT_SUCCESS}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)
                    return

                else:
                    d= {'requestID':msg["requestID"], 'action':msg["action"],
                        'exitstatus':EXIT_FAILURE, 'reason':'Signing request rejected by user'}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)
                    return

            else:
                d= {'requestID':msg['requestID'], 'action':msg['action'],
                    'exitstatus':EXIT_FAILURE, 'reason':'Action unknown'}
                reply= json.dumps(d)
                self.sendMessage(reply)
                logger.warning("Unknown action: "+action)
                return

        except Exception as e:
            # return failure code
            logger.warning('Exception: ' + repr(e))
            msg['exitstatus']=EXIT_FAILURE
            msg['reason']= repr(e)
            reply= json.dumps(msg)
            self.sendMessage(reply)
            cc.client.request('show_error','[handleMessage] Exception: '+repr(e))
            return

    #TODO: Only one connection at a time?
    def handleConnected(self):
        global cc, status, logger
        logger.debug('In handleConnected')
        logger.info(repr(self.address) + 'connected')

        # check origin (see https://github.com/ipython/ipython/pull/4845/files)
        try:
            ver= self.request.headers.get("Sec-WebSocket-Version")
            logger.debug("got ws version:"+str(ver))
            if ver  in ("7", "8"):
                origin_header = self.request.headers.get("Sec-Websocket-Origin")
            else:
                origin_header = self.request.headers.get("Origin")
        except Exception as e:
            logger.warning('Exception: ' + repr(e))

        # Set origin in electron: https://github.com/getsentry/sentry-electron/issues/176 /
        # https://github.com/arantes555/electron-fetch/issues/16
        # https://github.com/electron/electron/issues/7931
        # https://github.com/skevy/graphiql-app/pull/66/files
        msg= ("A new device wants to connect to Satochip:"+
                                                    "\n\tOrigin: "+ str(origin_header)+
                                                    "\n\tAddress:"+ str(self.address)+
                                                    "\n\nApprove connection?")
        (event, values)= cc.client.request('approve_action', msg)
        if event== 'No' or event== 'None':
            logger.info("Connection to Satochip was rejected!")
            self.close()
            return
        wallets[self]= values['skip_conf']
        logger.debug("Skip future confirmation for this connection? "+str(wallets[self]) )

    def handleClose(self):
        global logger
        wallets.pop(self)
        logger.info(self.address + 'closed')

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

def my_threaded_func(server):
    server.serveforever()

logger.info("Launching server...")
default_port= 8397 # 'Sa' in ascii, as in 'Satochip!'
server = SimpleWebSocketServer('', default_port, SatochipBridge)
thread = threading.Thread(target=my_threaded_func, args=(server,))
thread.start()
logger.info(f"Server launched on port {default_port}!")

logger.info("Launching system tray...")
cc.client.create_system_tray(cc.card_present)
