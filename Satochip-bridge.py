import hashlib
import json
import threading

from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket
from os import urandom

from CardConnector import CardConnector, UninitializedSeedError
from CardDataParser import CardDataParser
from JCconstants import JCconstants
from TxParser import TxParser
from ecc import ECPubkey
from Satochip2FA import Satochip2FA
from Client import Client, HandlerTxt, HandlerSimpleGUI

from smartcard.sw.SWExceptions import SWException
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest

#debug
from eth_keys import keys
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend

#handler= HandlerTxt()
handler= HandlerSimpleGUI()
client= Client(None, handler)
parser= CardDataParser()
cc = CardConnector(parser, client)
status= None
EXIT_SUCCESS=0
EXIT_FAILURE=1
               
# TODO list:
# Daemon mode
# Satochip initialization
# Logging
# DONE: Support 2FA
# DONE Check origin and host (+ whitelist?)
# DONE GUI

class SatochipBridge(WebSocket):
    
    def handleMessage(self):
        global cc, parser, status, EXIT_SUCCESS, EXIT_FAILURE
        print("In handleMessage()")
        print("DATA: "+str(type(self.data))+"  "+self.data)

        # parse msg
        try: 
            msg= json.loads(self.data)          
            action= msg["action"]
        except Exception as e:
            print("In handleMessage(): exception code 1")
            print(repr(e))
            
        try:
            if (action=="get_status"):
                response, sw1, sw2, status = cc.card_get_status()
                status["requestID"]= msg["requestID"]
                status["action"]= msg["action"]
                status['exitstatus']= EXIT_SUCCESS
                reply= json.dumps(status)
                self.sendMessage(reply)
                print("REPLY: "+reply)
                
            # if (action=="verify_pin"):
                # pin= msg["pin"]
                # cc.pin= list(pin.encode('utf-8'))
                # cc.card_verify_PIN()
                
            elif (action=="get_chaincode"):
                path= msg["path"]
                (depth, bytepath)= parser.bip32path2bytes(path)
                (pubkey, chaincode)= cc.card_bip32_get_extendedkey(bytepath)
                # convert to string
                pubkey= pubkey.get_public_key_hex(False) # non-compressed hexstring
                chaincode= chaincode.hex() # hexstring
                d= {'requestID':msg["requestID"], 'action':msg["action"], 'pubkey':pubkey, 'chaincode':chaincode, 'exitstatus':EXIT_SUCCESS}
                reply= json.dumps(d)
                self.sendMessage(reply)
                print("REPLY: "+reply)
                
                # #DEBUG
                # paths=["m/44'/1'/0'/0", "m/44'/60'/0'/0", "m/44'/61'/0'/0", "m/44'/1'/0'/1", "m/44'/60'/0'/1", "m/44'/61'/0'/1", 
                                # "m/44'/1'/0'/0/0", "m/44'/60'/0'/0/0", "m/44'/61'/0'/0/0", "m/44'/1'/0'/1/0", "m/44'/60'/0'/1/0", "m/44'/61'/0'/1/0",
                                # "m/44'/1'/0'/0/1", "m/44'/60'/0'/0/1", "m/44'/61'/0'/0/1", "m/44'/1'/0'/1/1", "m/44'/60'/0'/1/1", "m/44'/61'/0'/1/1",]
                # for path in paths:
                    # (depth, bytepath)= parser.bip32path2bytes(path)
                    # (pubkey, chaincode)= cc.card_bip32_get_extendedkey(bytepath)
                    # pubkey_bytes= pubkey.get_public_key_bytes(compressed=False)[1:] # non-compressed hexstring
                    # pubkey_hex= pubkey_bytes.hex() # non-compressed hexstring
                    # ethpubkey= KeyAPI.PublicKey(pubkey_bytes)
                    # print(" PATH:"+ path)
                    # print(" PUBKEY:"+ pubkey_hex)
                    # print(" ADDRESS:"+ ethpubkey.to_address())
                
            elif (action=="sign_tx_hash") or (action=="sign_msg_hash"):
            
                # prepare key corresponding to desired path
                path= msg["path"]
                (depth, bytepath)= parser.bip32path2bytes(path)
                (pubkey, chaincode)= cc.card_bip32_get_extendedkey(bytepath)
                print("SIGN with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                print("SIGN with hash: "+ msg["hash"])
                keynbr=0xFF
                hash= list(bytes.fromhex(msg["hash"]))
                
                if cc.needs_2FA:
                    #msg2FA= {'action':action, 'msg':message, 'alt':'etherlike'}
                    msg_2FA=  json.dumps(msg)
                    (id_2FA, msg_2FA)= cc.card_crypt_transaction_2FA(msg_2FA, True)
                    d={}
                    d['msg_encrypt']= msg_2FA
                    d['id_2FA']= id_2FA
                    print("encrypted message: "+msg_2FA)
                    print("id_2FA: "+id_2FA)
                    
                    #do challenge-response with 2FA device...
                    #print('2FA request sent! Approve or reject request on your second device.')
                    cc.client.handler.show_message('2FA request sent! Approve or reject request on your second device.')
                    Satochip2FA.do_challenge_response(d)
                    # decrypt and parse reply to extract challenge response
                    try: 
                        reply_encrypt= d['reply_encrypt']
                    except Exception as e:
                        print("No response received from 2FA.\nPlease ensure that the Satochip-2FA plugin is enabled in Tools>Optional Features", True)
                    reply_decrypt= cc.card_crypt_transaction_2FA(reply_encrypt, False)
                    print("challenge:response= "+ reply_decrypt)
                    reply_decrypt= reply_decrypt.split(":")
                    chalresponse=reply_decrypt[1]   
                    hmac= list(bytes.fromhex(chalresponse))
                else:
                    hmac=None
                
                if (hmac==20*[0]): # rejected by 2FA
                    d= {'requestID':msg["requestID"], 'action':msg["action"], "hash":msg["hash"], 
                        "sig":71*'00', "r":32*'00', "s":32*'00', "v":0 , "pubkey":pubkey.get_public_key_bytes().hex(),
                        'exitstatus':EXIT_FAILURE, 'reason':'Signing request rejected by 2FA'}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    print("REPLY: "+reply)
                else:
                    (response, sw1, sw2)=cc.card_sign_transaction_hash(keynbr, hash, hmac)
                    sig= bytearray(response).hex()
                    
                    # convert sig to rsv format:
                    print("convert sig to rsv format...")
                    try: 
                        compsig= parser.parse_hash_signature(response, bytes.fromhex(msg["hash"]), pubkey)
                    except Exception as e:
                        print(repr(e)) 
                    (r,s,v)= parser.parse_compact_sig_to_rsv(compsig)
                    
                    # # debug eth-keys
                    # print("    => =========== ETH-KEYS ============")
                    # latest_pubkey_bytes= pubkey.get_public_key_bytes(compressed=False)[1:]
                    # print("    => latest_pubkey_bytes:"+latest_pubkey_bytes.hex())
                    # ethpubkey= KeyAPI.PublicKey(latest_pubkey_bytes)
                    # print("    => latest_pubkey_address:"+ethpubkey.to_address())
                    # # recover pubkey from sig & hash
                    # ethcompsig= parser.parse_compact_sig_to_ethcompsig(compsig)
                    # print("    => ethcompsig:"+ethcompsig.hex())
                    # sig1= KeyAPI.Signature(signature_bytes=ethcompsig)
                    # ethpubkeyrec= KeyAPI.PublicKey.recover_from_msg_hash(bytes.fromhex(msg["hash"]), sig1)
                    # print("    => sig1:"+sig1.to_bytes().hex())
                    # print("    => recovered_pubkey:"+ethpubkeyrec.to_bytes().hex())
                    # print("    => recovered_pubkey_address:"+ethpubkeyrec.to_address())
                    # print("    => recovered_pubkey_checksum_address:"+ethpubkeyrec.to_checksum_address())
                    # #sig2=  KeyAPI.Signature(vrs)
                    # ethcompsig2= ethcompsig
                    # ethcompsig2[-1]= 0x00 if ethcompsig[-1]== 0x01 else 0x01
                    # sig2= KeyAPI.Signature(signature_bytes=ethcompsig2)
                    # ethpubkeyrec2= KeyAPI.PublicKey.recover_from_msg_hash(bytes.fromhex(msg["hash"]), sig2)
                    # print("    => sig2:"+sig2.to_bytes().hex())
                    # print("    => recovered_pubkey2:"+ethpubkeyrec2.to_bytes().hex())
                    # print("    => recovered_pubkey_address:"+ethpubkeyrec2.to_address())
                    # print("    => recovered_pubkey_checksum_address:"+ethpubkeyrec2.to_checksum_address())
                    # print("    => =========== ETH-KEYS ============")

                    d= {'requestID':msg["requestID"], 'action':msg["action"], "hash":msg["hash"], 
                                "sig":sig, "r":r.hex(), "s":s.hex(), "v":v , "pubkey":pubkey.get_public_key_bytes().hex(),
                                'exitstatus':EXIT_SUCCESS}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    print("REPLY: "+reply)    
                
            else:
                d= {'requestID':msg['requestID'], 'action':msg['action'], 'exitstatus':EXIT_FAILURE, 'reason':'Action unknown'}
                reply= json.dumps(d)
                self.sendMessage(reply)
                print("UNKNOWN ACTION: "+action)
                
        except Exception as e:
            print("In handleMessage(): exception CC")
            print(repr(e))
            try:
                cc.card_disconnect()
                cc = CardConnector(parser)
            except Exception as e:
                print("In handleMessage(): exception DD")
                print(repr(e))
            
    def handleConnected(self):
        global cc, parser, status
        print(self.address, 'connected')
        
        # check origin (see https://github.com/ipython/ipython/pull/4845/files)        
        try: 
            ver= self.request.headers.get("Sec-WebSocket-Version")
            print("In handleMessage(): got ws version:"+str(ver))
            if ver  in ("7", "8"):
                origin_header = self.request.headers.get("Sec-Websocket-Origin")
            else:
                origin_header = self.request.headers.get("Origin")
        except Exception as e:
            print(repr(e))    
        # Set origin in electron: https://github.com/getsentry/sentry-electron/issues/176 / 
        # https://github.com/arantes555/electron-fetch/issues/16
        # https://github.com/electron/electron/issues/7931
        # https://github.com/skevy/graphiql-app/pull/66/files
        print(str(type(origin_header))) # BUG!!!!
        if origin_header:
            print("CHECK: origin_header:"+str(origin_header)) # BUG!!!!
        print("CHECK HOST: "+str(type(self.address))+" "+str(self.address))
        is_approved= cc.client.handler.yes_no_question("A new device wants to connect to Satochip:"+
                                                    "\nOrigin: "+ str(origin_header)+
                                                    "\nAddress:"+ str(self.address)+
                                                    "\n\nApprove connection?")
        if not is_approved:
            print("Connection to Satochip was rejected!")
            self.handleClose()
            return
        
        try:
            print("handleConnected(): card_init_connect")#debugSatochip
            cc.card_init_connect()
        except Exception as e:
            print("In handleConnected(): exception during card_init_connect")
            print(repr(e))
            try:
                cc.card_disconnect()
                cc = CardConnector(parser)
            except Exception as e:
                print("In handleConnected(): exception DD")
                print(repr(e))

    def handleClose(self):
        global cc, parser
        cc.card_disconnect()
        print(self.address, 'closed')



cc.card_init_connect()
#cc.client.handler.seed_wizard()
#cc.client.handler.QRDialog(20*"00", None, "Satochip-Bridge: QR Code", True, "2FA: ")
#cc.client.handler.choose_seed_action()
#cc.client.handler.create_seed("AA BB CC DD EE FF")
#cc.client.handler.request_passphrase()
#cc.client.handler.confirm_seed()
#cc.client.handler.confirm_passphrase()

def my_threaded_func(server):
    print("Launching server!")
    server.serveforever()
    print("Done!")

# def my_threaded_func(cc):
    # print("Running system tray!")
    # cc.client.handler.system_tray()
    # print("Done!")
# # start system tray in thread
# thread = threading.Thread(target=my_threaded_func, args=(cc,))
# thread.start()
# print("System tray launched!")


server = SimpleWebSocketServer('', 8000, SatochipBridge)
#server.serveforever()
# start server in thread
thread = threading.Thread(target=my_threaded_func, args=(server,))
thread.start()
print("Server launched!")

# print("Running system tray!")
cc.client.handler.system_tray()
