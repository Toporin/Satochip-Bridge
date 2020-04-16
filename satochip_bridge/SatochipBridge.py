import json
import threading
import time
 
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket
from os import urandom

try: 
    from CardConnector import CardConnector, UninitializedSeedError
    from CardDataParser import CardDataParser
    from JCconstants import JCconstants
    from Satochip2FA import Satochip2FA
    from Client import Client, HandlerTxt, HandlerSimpleGUI
    #from TxParser import TxParser
    #from ecc import ECPubkey, CURVE_ORDER, der_sig_from_r_and_s, get_r_and_s_from_der_sig
except Exception as e:
    print("Import exception")
    print(repr(e))
    from satochip_bridge.CardConnector import CardConnector, UninitializedSeedError
    from satochip_bridge.CardDataParser import CardDataParser
    from satochip_bridge.JCconstants import JCconstants
    from satochip_bridge.Satochip2FA import Satochip2FA
    from satochip_bridge.Client import Client, HandlerTxt, HandlerSimpleGUI
    #from satochip_bridge.TxParser import TxParser
    #from satochip_bridge.ecc import ECPubkey, CURVE_ORDER, der_sig_from_r_and_s, get_r_and_s_from_der_sig

#debug
try:
    from eth_keys import keys
except Exception as e:
    print("Import exception for eth_keys")
    print(repr(e))
    import os
    try:
        user_paths = os.environ['PYTHONPATH'].split(os.pathsep)
        print("PYTHONPATH:")
        print(repr(user_paths))
    except KeyError:
        print("KeyError")
        print(repr(e))
        user_paths = []
        print("user_paths = []")

try:
    from eth_keys import KeyAPI
except Exception as e:
    print("Import exception for eth_keys keyAPI")
    print(repr(e))
    
try:
    from eth_keys.backends import NativeECCBackend
except Exception as e:
    print("Import exception for eth_keys NativeECCBackend")
    print(repr(e))
    
#handler= HandlerTxt()
handler= HandlerSimpleGUI()
client= Client(None, handler)
parser= CardDataParser()
cc = CardConnector(parser, client)
status= None
EXIT_SUCCESS=0
EXIT_FAILURE=1
               
# TODO list:
#versioning
# authentikey image
# Logging
# Daemon mode
# DONE: Support 2FA
# DONE Check origin and host (+ whitelist?)
# DONE GUI
# DONE Satochip initialization

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
                    notif= '2FA request sent! Approve or reject request on your second device.'
                    cc.client.request('show_notification', notif)
                    #cc.client.request('show_message', notif)
                    Satochip2FA.do_challenge_response(d)
                    # decrypt and parse reply to extract challenge response
                    try: 
                        reply_encrypt= d['reply_encrypt']
                    except Exception as e:
                        cc.client.request('show_error', "No response received from 2FA...")
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
                    hash= list(bytes.fromhex(msg["hash"]))
                    (response, sw1, sw2)=cc.card_sign_transaction_hash(keynbr, hash, hmac)
                    
                    # ## enforce low-S signature (BIP 62)
                    # tx_sig = bytearray(response)
                    # r,s= get_r_and_s_from_der_sig(tx_sig) #r,s:long int
                    # if s > CURVE_ORDER//2:
                        # print('DEBUG: S is higher than CURVE_ORDER//2')
                        # s = CURVE_ORDER - s
                        # tx_sig=der_sig_from_r_and_s(r, s)
                    # r= format(r, 'x') #hex
                    # s= format(s, 'x')
                    # print("DEBUG: r_old=", r)
                    # print("DEBUG: s_old=", s)
                    
                    # convert sig to rsv format:
                    print("convert sig to rsv format...")
                    try: 
                        #compsig= parser.parse_hash_signature(response, bytes.fromhex(msg["hash"]), pubkey)
                        (r,s,v, sigstring)= parser.parse_rsv_from_dersig(bytes(response), bytes.fromhex(msg["hash"]), pubkey) 
                        # r,s,v:int convert to hex (64-char padded with 0)
                        r= "{0:0{1}x}".format(r,64) 
                        s= "{0:0{1}x}".format(s,64) 
                        print ("sigstring", sigstring.hex())
                        print ("r", r)
                        print ("s", s)
                        print ("v", v)
                    except Exception as e:
                        print("[handleMessage] in parse_rsv_from_dersig: ", repr(e)) 
                        
                    # #old    
                    # (r2,s2,v2)= parser.parse_compact_sig_to_rsv(compsig) #r2,s2: bytes
                    # print ("compsig", compsig.hex())
                    # print("DEBUG: r2=", r2.hex())
                    # print("DEBUG: s2=", s2.hex())
                    # print("DEBUG: v2=", v2)
                    
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
                                "sig":sigstring.hex(), "r":r, "s":s, "v":v, "pubkey":pubkey.get_public_key_bytes().hex(),
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
            print('[handleMessage] Exception: ',repr(e))
            cc.client.request('show_error','[handleMessage] Exception: '+repr(e))
            
            # try:
                # cc.card_disconnect()
                # cc = CardConnector(parser)
            # except Exception as e:
                # print("In handleMessage(): exception DD")
                # print(repr(e))
    
    #TODO: Only one connection at a time?
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
        msg= ("A new device wants to connect to Satochip:"+
                                                    "\nOrigin: "+ str(origin_header)+
                                                    "\nAddress:"+ str(self.address)+
                                                    "\n\nApprove connection?")
        is_approved= cc.client.request('yes_no_question', msg)
        if not is_approved:
            print("Connection to Satochip was rejected!")
            #self.handleClose()
            self.close()
            return
        
        try:
            cc.card_init_connect()
        except Exception as e:
            cc.client.request('show_error','[handleConnected] Exception:'+repr(e))
            print('[handleConnected] Exception:'+repr(e))
            # try:
                # cc.card_disconnect()
                # cc = CardConnector(parser)
            # except Exception as e:
                # print("In handleConnected(): exception DD")
                # print(repr(e))

    def handleClose(self):
        global cc, parser
        print(self.address, 'closed')
        
        
#debug
#cc.card_init_connect()
#cc.client.handler.seed_wizard()
#cc.client.handler.QRDialog(20*"00", None, "Satochip-Bridge: QR Code", True, "2FA: ")
#cc.client.handler.choose_seed_action()
#cc.client.handler.create_seed("AA BB CC DD EE FF")
#cc.client.handler.request_passphrase()
#cc.client.handler.confirm_seed()
#cc.client.handler.confirm_passphrase()
#cc.client.handler.restore_from_seed()

def my_threaded_func(server):
    #time.sleep(10) # delay server until system tray is ready
    server.serveforever()
    
print("Launching server!")
server = SimpleWebSocketServer('', 8000, SatochipBridge)
thread = threading.Thread(target=my_threaded_func, args=(server,))
thread.start()
print("Server launched!")

print("Running system tray!")
cc.client.create_system_tray(cc.card_present)

