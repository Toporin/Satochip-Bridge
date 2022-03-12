import threading
import logging
from os import urandom
from queue import Queue 

from pysatochip.CardConnector import CardConnector, UninitializedSeedError
from pysatochip.JCconstants import JCconstants
from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION

# WalletConnect
from pywalletconnectv1.wc_client import WCClient
from pywalletconnectv1.models.wc_peer_meta import WCPeerMeta
from pywalletconnectv1.models.session.wc_session import WCSession

try: 
    from wc_callback import WCCallback
except Exception as e:
    print('ImportError: '+repr(e))
    from satochip_bridge.wc_callback import WCCallback

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

MSG_USE_2FA= ("Do you want to use 2-Factor-Authentication (2FA)?\n\n"
                "With 2FA, any transaction must be confirmed on a second device such as \n"
               "your smartphone. First you have to install the Satochip-2FA android app on \n"
               "google play. Then you have to pair your 2FA device with your Satochip \n"
               "by scanning the qr-code on the next screen. \n"
               "Warning: be sure to backup a copy of the qr-code in a safe place, \n"
               "in case you have to reinstall the app!")
               
class Client:

    def __init__(self, cc, handler, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        self.handler = handler
        self.handler.client= self
        self.queue_request= Queue()
        self.queue_reply= Queue()
        self.cc= cc
        # WalletConnect
        self.wc_callback= WCCallback(None, self, self.handler) # todo: put in handler?
       
    def create_system_tray(self, card_present):
        self.handler.system_tray(card_present)
    
    def request(self, request_type, *args):
        logger.debug('Client request: '+ str(request_type))
        
        # bypass queue-based data exchange between main GUI thread and   
        # server thread when request comes directly from the main thread.
        if threading.current_thread() is threading.main_thread():
            #TODO: check if handler exist
            logger.debug('In main thread:')
            method_to_call = getattr(self.handler, request_type)
            #logger.debug('Type of method_to_call: '+ str(type(method_to_call)))
            #logger.debug('Method_to_call: '+ str(method_to_call))
            reply = method_to_call(*args)
            return reply 
        
        # we use a queue to exchange request between the server thread and the main (GUI) thread
        self.queue_request.put((request_type, args))
        logger.debug('In second thread:')
        
        # Get some data 
        try:
            #todo: check if several message are sent...
            #(reply_type, reply)= self.queue_reply.get(block=True, timeout=5)  #TODO: check if blocking
            (reply_type, reply)= self.queue_reply.get(block=True, timeout=None)  #TODO: check if blocking
            if (reply_type != request_type):
                # should not happen #todo: clean the queues
                RuntimeError("Reply mismatch during GUI handler notification!")
            else:
                return reply
        except Exception as exc:
            self.request('show_error', "[Client] Exception in request(): "+repr(exc))
            return None
        
    def PIN_dialog(self, msg):
        while True:
            (is_PIN, pin) = self.request('get_passphrase',msg)
            if (not is_PIN) or (pin is None): # if 'cancel' or windows closed
                 return (False, None)
            elif len(pin) < 4:
                msg = ("PIN must have at least 4 characters.") + \
                      "\n\n" + ("Enter PIN:")
            elif len(pin) > 64:
                msg = ("PIN must have less than 64 characters.") + \
                      "\n\n" + ("Enter PIN:")
            else:
                pin = pin.encode('utf8')
                return (True, pin)
    
    def PIN_setup_dialog(self, msg, msg_confirm, msg_error):
        while(True):
            (is_PIN, pin)= self.PIN_dialog(msg)
            if not is_PIN:
                return (False, None) #raise RuntimeError(('A PIN code is required to initialize the Satochip!'))
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if not is_PIN:
                return (False, None) #raise RuntimeError(('A PIN confirmation is required to initialize the Satochip!'))
            if (pin != pin_confirm):
                self.request('show_error', msg_error)
            else:
                return (is_PIN, pin)
     
    def PIN_change_dialog(self, msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel):
        
        (is_PIN, oldpin)= self.PIN_dialog(msg_oldpin)
        if (not is_PIN):
            self.request('show_message', msg_cancel)
            return (False, None, None)

        # new pin
        while (True):
            (is_PIN, newpin)= self.PIN_dialog(msg_newpin)
            if (not is_PIN):
                self.request('show_message', msg_cancel)
                return (False, None, None)
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if (not is_PIN):
                self.request('show_message', msg_cancel)
                return (False, None, None)
            if (newpin != pin_confirm):
                self.request('show_error', msg_error)
            else:
                return (True, oldpin, newpin)
    
    ########################################
    #             Setup functions                              #
    ########################################
    
    def card_init_connect(self):
        
        # check setup
        if (self.cc.card_present) and (self.cc.card_type == "Satochip"):
            #logger.info("ATR: "+str(self.cc.card_get_ATR()))
            (response, sw1, sw2, d)=self.cc.card_get_status()
            
            # check version
            if  (self.cc.setup_done):
                #v_supported= CardConnector.SATOCHIP_PROTOCOL_VERSION 
                v_supported= SATOCHIP_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"Satochip version={hex(v_applet)} Electrum supported version= {hex(v_supported)}")#debugSatochip
                if (v_supported<v_applet):
                    msg=(('The version of your Satochip is higher than supported by Electrum. You should update Electrum to ensure correct functioning!')+ '\n' 
                                + f'    Satochip version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                + f'    Supported version: {SATOCHIP_PROTOCOL_MAJOR_VERSION}.{SATOCHIP_PROTOCOL_MINOR_VERSION}')
                    self.request('show_error', msg)
                
                if (self.cc.needs_secure_channel):
                    self.cc.card_initiate_secure_channel()
                
            # setup device (done only once)
            else:
                # PIN dialog
                msg = ("Enter a new PIN for your Satochip:")
                msg_confirm = ("Please confirm the PIN code for your Satochip:")
                msg_error = ("The PIN values do not match! Please type PIN again!")
                (is_PIN, pin_0)= self.PIN_setup_dialog(msg, msg_confirm, msg_error)
                if not is_PIN:
                    #raise RuntimeError('A PIN code is required to initialize the Satochip!')
                    logger.warning('Initialization aborted: a PIN code is required to initialize the Satochip!')
                    self.request('show_error', 'A PIN code is required to initialize the Satochip.\nInitialization aborted!')
                    return
                    
                pin_0= list(pin_0)
                pin_tries_0= 0x05;
                ublk_tries_0= 0x01;
                # PUK code can be used when PIN is unknown and the card is locked
                # We use a random value as the PUK is not used currently and is not user friendly
                ublk_0= list(urandom(16)); 
                pin_tries_1= 0x01
                ublk_tries_1= 0x01
                pin_1= list(urandom(16)); #the second pin is not used currently
                ublk_1= list(urandom(16));
                secmemsize= 32 # number of slot reserved in memory cache
                memsize= 0x0000 # RFU
                create_object_ACL= 0x01 # RFU
                create_key_ACL= 0x01 # RFU
                create_pin_ACL= 0x01 # RFU
                
                #setup
                (response, sw1, sw2)=self.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1!=0x90 or sw2!=0x00:       
                    logger.warning(f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")
                    self.request('show_error', f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")
                    return
                    #raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
            
            # verify pin:
            try: 
                self.cc.card_verify_PIN()
            except RuntimeError as ex:
                logger.warning(repr(ex))
                self.request('show_error', repr(ex))
                return
            
            # get authentikey
            try:
                authentikey=self.cc.card_bip32_get_authentikey()
            except UninitializedSeedError:
                # Option: setup 2-Factor-Authentication (2FA)
                self.init_2FA()
                        
                # seed dialog...
                (mnemonic, passphrase, seed)= self.seed_wizard()                    
                if seed:
                    seed= list(seed)
                    authentikey= self.cc.card_bip32_import_seed(seed)
                    if authentikey:
                        self.request('show_success','Seed successfully imported to Satochip!')
                        hex_authentikey= authentikey.get_public_key_hex(compressed=True)
                        logger.info(f"Authentikey={hex_authentikey}")
                    else:
                        self.request('show_error','Error when importing seed to Satochip!')
                else: #if cancel
                    self.request('show_message','Seed import cancelled!')
            
        else: 
            self.request('show_error','No card found! Please insert a Satochip and try again...')

        
    def init_2FA(self, from_backup=False):
        logger.debug("In init_2FA")
        if not self.cc.needs_2FA:
            use_2FA=self.request('yes_no_question', MSG_USE_2FA)
            if (use_2FA):
                if (from_backup):
                    (event, values)= self.request('import_2FA_backup')
                    if event == None or event == 'Cancel':
                        self.request('show_message', '2FA activation canceled!')     
                        return
                    secret_2FA_hex= values['secret_2FA']
                    secret_2FA= bytes.fromhex(secret_2FA_hex)
                else:
                    secret_2FA= urandom(20)
                    secret_2FA_hex=secret_2FA.hex()
                amount_limit= 0 # i.e. always use 
                try:
                    # the secret must be shared with the second factor app (eg on a smartphone)
                    msg= 'Scan this QR code on your second device \nand securely save a backup of this 2FA-secret: \n'+secret_2FA_hex
                    (event, values)= self.request('QRDialog', secret_2FA_hex, None, "Satochip-Bridge: QR Code", True, msg)
                    if event=='Ok':
                        # further communications will require an id and an encryption key (for privacy). 
                        # Both are derived from the secret_2FA using a one-way function inside the Satochip
                        (response, sw1, sw2)=self.cc.card_set_2FA_key(secret_2FA, amount_limit)
                        if sw1!=0x90 or sw2!=0x00:                 
                            logger.warning("Unable to set 2FA!  sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
                            self.request('show_error', 'Unable to setup 2FA with error code:'+hex(sw1)+' '+hex(sw2))
                            #raise RuntimeError('Unable to setup 2FA with error code:'+hex(sw1)+' '+hex(sw2))
                        else:
                            self.request('show_success', '2FA enabled successfully!')
                    else: # Cancel
                        self.request('show_message', '2FA activation canceled!')
                except Exception as e:
                    logger.warning("Exception during 2FA activation: "+str(e))    
                    self.request('show_error', 'Exception during 2FA activation: '+str(e))
        else:
            self.request('show_message', '2FA is already activated!')
            
    def seed_wizard(self): 
        logger.debug("In seed_wizard()") #debugSatochip
            
        from mnemonic import Mnemonic
        # state: state_choose_seed_action - state_create_seed -  state_request_passphrase - state_confirm_seed  - state_confirm_passphrase - state_abort
        # state: state_choose_seed_action - state_restore_from_seed - state_request_passphrase - state_abort
        state= 'state_choose_seed_action'    
        
        while (True):
            if (state=='state_choose_seed_action'):
                mnemonic= None
                passphrase= None
                seed= None
                needs_confirm= None
                use_passphrase= None
                (event, values)= self.request('choose_seed_action')
                if (event =='Next') and (values['create'] is True):
                    state='state_create_seed'
                elif (event =='Next') and (values['restore'] is True):
                    state= 'state_restore_from_seed'
                else: # cancel
                    state= 'state_abort'
                    break
                    
            elif (state=='state_create_seed'):
                needs_confirm= True
                MNEMONIC = Mnemonic(language="english")
                mnemonic = MNEMONIC.generate(strength=128)
                if MNEMONIC.check(mnemonic):    
                    (event, values)= self.request('create_seed', mnemonic)
                    if (event=='Next') and (values['use_passphrase'] is True):
                        use_passphrase= True
                        state= 'state_request_passphrase'
                    elif (event=='Next') and not values['use_passphrase']:
                        use_passphrase= False
                        state= 'state_confirm_seed'
                    else: #Back
                        state= 'state_choose_seed_action'
                else:  #should not happen
                    #raise ValueError("Invalid BIP39 seed!")
                    logger.warning("Invalid BIP39 seed!")
                    self.request('show_error', "Invalid BIP39 seed!")
                    state= 'state_choose_seed_action'
                
            elif (state=='state_request_passphrase'):                        
                (event, values)= self.request('request_passphrase')
                if (event=='Next'):
                    passphrase= values['passphrase']
                    if (needs_confirm):
                        state= 'state_confirm_seed'
                    else:
                       break #finished
                else: #Back
                    state= 'state_choose_seed_action'
                
            elif (state=='state_confirm_seed'):               
                (event, values)= self.request('confirm_seed')
                mnemonic_confirm= values['seed_confirm']
                if (event=='Next') and (mnemonic== mnemonic_confirm):
                    if (use_passphrase):
                        state= 'state_confirm_passphrase'
                    else:
                        break #finish!
                elif (event=='Next') and (mnemonic!= mnemonic_confirm):
                    self.request('show_error','Seed mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
                    
            elif (state=='state_confirm_passphrase'):            
                (event, values)= self.request('confirm_passphrase')
                passphrase_confirm= values['passphrase_confirm']
                if (event=='Next') and (passphrase== passphrase_confirm):
                    break #finish!
                elif (event=='Next') and (passphrase!= passphrase_confirm):
                    self.request('show_error','Passphrase mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
            
            elif (state== 'state_restore_from_seed'):
                needs_confirm= False
                (event, values)= self.request('restore_from_seed')
                mnemonic= values['seed']
                use_passphrase= values['use_passphrase']
                if (event=='Next') and use_passphrase:
                    state= 'state_request_passphrase'
                elif (event=='Next') and not use_passphrase:
                    break #finished!
                else: #Back
                    state= 'state_choose_seed_action'
            
            else:
                logger.warning('State error!')
        
        if mnemonic is None:
            self.request('show_message', "Seed initialization aborted! \nYour Satochip may be unusable until a seed is created... \n Go to 'menu' -> 'Setup new Satochip' to complete setup")
        passphrase='' if passphrase is None else passphrase
        seed= Mnemonic.to_seed(mnemonic, passphrase) if mnemonic else None
        #print('mnemonic: '+ str(mnemonic))
        #print('passphrase: '+str(passphrase))
        #print('seed: '+str(seed.hex()))
        
        return (mnemonic, passphrase, seed)
        