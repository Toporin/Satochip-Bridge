import json
import threading
import time
import logging
import sys
import os.path
#import traceback

from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

from pysatochip.CardConnector import CardConnector #, UninitializedSeedError
from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST
#from pysatochip.JCconstants import JCconstants
#from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION

# from Client import Client
# from handler import HandlerTxt, HandlerSimpleGUI

try: 
    from Client import Client
    from handler import HandlerTxt, HandlerSimpleGUI
    from sato2FA import Sato2FA
except Exception as e:
    print('ImportError: '+repr(e))
    from satochip_bridge.Client import Client
    from satochip_bridge.handler import HandlerTxt, HandlerSimpleGUI
    from satochip_bridge.sato2FA import Sato2FA

# try:
    # from eth_keys import keys, KeyAPI
    # from eth_keys.backends import NativeECCBackend
# except Exception as e:
    # print("Import exception for eth_keys")
    # print(repr(e))

if (len(sys.argv)>=2) and (sys.argv[1]in ['-v', '--verbose']):
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)

logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )

#handler= HandlerTxt()
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
                
            elif (action=="sign_tx_hash") or (action=="sign_msg_hash"):
                
                # prepare key corresponding to desired path
                path= msg["path"]
                #(depth, bytepath)= parser.bip32path2bytes(path)
                (pubkey, chaincode)= cc.card_bip32_get_extendedkey(path)
                logger.debug("Sign with pubkey: "+ pubkey.get_public_key_bytes(compressed=False).hex())
                logger.debug("Sign hash: "+ msg["hash"])
                keynbr=0xFF
                
                is_approved= False
                hmac= None
                if cc.needs_2FA:
                    #msg2FA= {'action':action, 'msg':message, 'alt':'etherlike'}
                    (is_approved, hmac)= Sato2FA.do_challenge_response(client, msg)
                    
                    # msg_2FA=  json.dumps(msg)
                    # (id_2FA, msg_2FA)= cc.card_crypt_transaction_2FA(msg_2FA, True)
                    # d={}
                    # d['msg_encrypt']= msg_2FA
                    # d['id_2FA']= id_2FA
                    # logger.debug("encrypted message: "+msg_2FA)
                    # logger.debug("id_2FA: "+ id_2FA)
                    
                    # try: 
                        # # get server from config file
                        # if os.path.isfile('satochip_bridge.ini'):  
                            # from configparser import ConfigParser
                            # config = ConfigParser()
                            # config.read('satochip_bridge.ini')
                            # server_default= config.get('2FA', 'server_default')
                        # else:
                            # server_default= SERVER_LIST[0] # no config file => default server
                        # #do challenge-response with 2FA device...
                        # notif= '2FA request sent! Approve or reject request on your second device.'
                        # cc.client.request('show_notification', 'Notification', notif)
                        # #cc.client.request('show_message', notif)
                        # Satochip2FA.do_challenge_response(d, server_default)
                        # # decrypt and parse reply to extract challenge response
                        # reply_encrypt= d['reply_encrypt']
                        # reply_decrypt= cc.card_crypt_transaction_2FA(reply_encrypt, False)
                    # except Exception as e:
                        # cc.client.request('show_error', "No response received from 2FA...")
                        # msg['exitstatus']=EXIT_FAILURE
                        # msg['reason']= "No response received from 2FA"
                        # reply= json.dumps(msg)
                        # self.sendMessage(reply)
                        # return
                    # logger.debug("challenge:response= "+ reply_decrypt)
                    # reply_decrypt= reply_decrypt.split(":")
                    # chalresponse=reply_decrypt[1]   
                    # hmac= list(bytes.fromhex(chalresponse))
                    # notif= 'Received response from 2FA device!'
                    # cc.client.request('show_notification', 'Notification', notif)
                else:
                    logger.debug("Skip confirmation for this action? "+ str(wallets[self]) )
                    if not wallets[self]: #if confirm required
                        request_action= "sign a message" if action=="sign_msg_hash" else "sign a transaction"
                        request_msg= ("A client wants to perform the following on your Satochip:"+
                                                        "\n\tAction: "+ request_action +
                                                        "\n\tAddress:"+ str(self.address)+
                                                        "\n\nApprove action?")
                        (event, values)= cc.client.request('approve_action', request_msg)
                        if event== 'No' or event== 'None':
                            #hmac=20*[0] # will trigger reject   
                            is_approved= False
                        else:
                            is_approved= True
                            wallets[self]= values['skip_conf']
                
                if not is_approved:
                    d= {'requestID':msg["requestID"], 'action':msg["action"], "hash":msg["hash"], 
                        "sig":71*'00', "r":32*'00', "s":32*'00', "v":0 , "pubkey":pubkey.get_public_key_bytes().hex(),
                        'exitstatus':EXIT_FAILURE, 'reason':'Signing request rejected by user'}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)    
                    return
                else:
                    hash= list(bytes.fromhex(msg["hash"]))
                    (response, sw1, sw2)=cc.card_sign_transaction_hash(keynbr, hash, hmac)
                    
                    # convert sig to rsv format:
                    logger.debug ("Convert sig to rsv format...")
                    try: 
                        #compsig= parser.parse_hash_signature(response, bytes.fromhex(msg["hash"]), pubkey)
                        (r,s,v, sigstring)= cc.parser.parse_rsv_from_dersig(bytes(response), bytes.fromhex(msg["hash"]), pubkey) 
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
                        msg['exitstatus']=EXIT_FAILURE
                        msg['reason']= "Exception in parse_rsv_from_dersig"
                        reply= json.dumps(msg)
                        self.sendMessage(reply)
                        return
                    d= {'requestID':msg["requestID"], 'action':msg["action"], "hash":msg["hash"], 
                                "sig":sigstring.hex(), "r":r, "s":s, "v":v, "pubkey":pubkey.get_public_key_bytes().hex(),
                                'exitstatus':EXIT_SUCCESS}
                    reply= json.dumps(d)
                    self.sendMessage(reply)
                    logger.debug("Reply: "+reply)    
                    return
                    
            else:
                d= {'requestID':msg['requestID'], 'action':msg['action'], 'exitstatus':EXIT_FAILURE, 'reason':'Action unknown'}
                reply= json.dumps(d)
                self.sendMessage(reply)
                logger.warning("Unknown action: "+action)
                
        except Exception as e:
            # return failure code
            logger.warning('Exception: ' + repr(e))
            msg['exitstatus']=EXIT_FAILURE
            msg['reason']= repr(e)
            reply= json.dumps(msg)
            self.sendMessage(reply)
            cc.client.request('show_error','[handleMessage] Exception: '+repr(e))
            return
            #traceback.print_exc()
    
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
            
        #is_approved= cc.client.request('yes_no_question', msg)
        # if not is_approved:
            # logger.info("Connection to Satochip was rejected!")
            # self.close()
            # return
        
        # We do not touch the card until we receive an actual request (in handleMessage)
        # try:
            # cc.client.card_init_connect()
        # except Exception as e:
            # cc.client.request('show_error','[handleConnected] Exception:'+repr(e))
            # logger.warning('Exception:'+repr(e))
            
    def handleClose(self):
        global logger
        wallets.pop(self)
        logger.info(self.address + 'closed')
        

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
