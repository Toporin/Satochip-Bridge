import json
import logging
import sys
import os.path

from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST

logger = logging.getLogger(__name__)

EXIT_SUCCESS=0
EXIT_FAILURE=1

class Sato2FA:
            
    @classmethod
    def do_challenge_response(cls, client, msg):
        #msg2FA= {'action':action, 'msg':message, 'alt':'etherlike'}
        is_approved= False
        msg_2FA=  json.dumps(msg)
        (id_2FA, msg_2FA)= client.cc.card_crypt_transaction_2FA(msg_2FA, True)
        d={}
        d['msg_encrypt']= msg_2FA
        d['id_2FA']= id_2FA
        logger.debug("encrypted message: "+msg_2FA)
        logger.debug("id_2FA: "+ id_2FA)
        
        try: 
            # get server from config file
            if os.path.isfile('satochip_bridge.ini'):  
                from configparser import ConfigParser
                config = ConfigParser()
                config.read('satochip_bridge.ini')
                server_default= config.get('2FA', 'server_default')
            else:
                server_default= SERVER_LIST[0] # no config file => default server
            #do challenge-response with 2FA device...
            notif= '2FA request sent! Approve or reject request on your second device.'
            client.request('show_notification', 'Notification', notif)
            Satochip2FA.do_challenge_response(d, server_default)
            # decrypt and parse reply to extract challenge response
            reply_encrypt= d['reply_encrypt']
            reply_decrypt= client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
        except Exception as e:
            hmac= 20*[0xff]
            is_approved= False
            client.request('show_error', "No response received from 2FA...")
            return (is_approved, hmac)
        
        logger.debug("challenge:response= "+ reply_decrypt)
        reply_decrypt= reply_decrypt.split(":")
        chalresponse=reply_decrypt[1]   
        hmac= list(bytes.fromhex(chalresponse))
        if hmac == 20*[0]:
            is_approved= False
            notif= 'Request rejected by 2FA device!'
        else:
            is_approved= True
            notif= 'Request approved by 2FA device!'
        client.request('show_notification', 'Notification', notif)
        return (is_approved, hmac)
