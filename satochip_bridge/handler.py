#import PySimpleGUI as sg   
#import PySimpleGUIWx as sg 
import PySimpleGUIQt as sg 
import base64    
import getpass
import pyperclip
#from pyperclip import PyperclipException
import sys
import os
import logging
import re
from queue import Queue 
from configparser import ConfigParser    
from pykson import Pykson

# WalletConnect
from pywalletconnectv1.wc_session_store_item import WCSessionStoreItem
from pywalletconnectv1.models.wc_peer_meta import WCPeerMeta
from pywalletconnectv1.models.session.wc_session import WCSession

from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST
from pysatochip.CardConnector import CardConnector, UninitializedSeedError
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION, PYSATOCHIP_VERSION

try: 
    from version import SATOCHIP_BRIDGE_VERSION
except Exception as e:
    print('ImportError: '+repr(e))
    from satochip_bridge.version import SATOCHIP_BRIDGE_VERSION

# WalletConnect
try: 
    from wc_callback import WCCallback
except Exception as e:
    print('ImportError: '+repr(e))
    from satochip_bridge.wc_callback import WCCallback

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
  
class HandlerTxt:
    def __init__(self):
        pass

    def update_status(self, isConnected):
        if (isConnected):
            print("Card connected!")
        else:
            print("Card disconnected!")

    def show_error(self,msg):
        print(msg)
    
    def show_success(self, msg):
        print(msg)
        
    def show_message(self, msg):
        print(msg)
    
    def yes_no_question(self, question):
        while "the answer is invalid":
            reply = str(input(question+' (y/n): ')).lower().strip()
            if reply[0] == 'y':
                return True
            if reply[0] == 'n':
                return False
        
    def get_passphrase(self, msg): 
        is_PIN=True
        pin = getpass.getpass(msg) #getpass returns a string
        return (is_PIN, pin)
        
    def QRDialog(self, data, parent=None, title = '', show_text=False, msg= ''):
        print(msg)

class HandlerSimpleGUI:
    def __init__(self, loglevel= logging.WARNING): 
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        sg.theme('BluePurple')
        # absolute path to python package folder of satochip_bridge ("lib")
        #self.pkg_dir: the path where the app folder is located, for executable, the folder is extracted to a temp folder 
        if getattr( sys, 'frozen', False ):
            # running in a bundle
            self.pkg_dir= sys._MEIPASS # for pyinstaller
        else :
            # running live
            self.pkg_dir = os.path.split(os.path.realpath(__file__))[0]
        logger.debug("PKGDIR= " + str(self.pkg_dir))
        self.satochip_icon= self.icon_path("satochip.png") #"satochip.png"
        self.satochip_unpaired_icon= self.icon_path("satochip_unpaired.png") #"satochip_unpaired.png"
         # WalletConnect
        self.wc_callback= WCCallback(sato_client=None, sato_handler=self) # sato_client is not available during init
         
    def icon_path(self, icon_basename):
        #return resource_path(icon_basename)
        return os.path.join(self.pkg_dir, icon_basename)
    
    def update_status(self, isConnected):
        if (isConnected):
            self.tray.update(filename=self.satochip_icon) #self.tray.update(filename=r'satochip.png')
        else:
            self.tray.update(filename=self.satochip_unpaired_icon) #self.tray.update(filename=r'satochip_unpaired.png')
            
    def show_error(self, msg):
        sg.popup('Satochip-Bridge Error!', msg, icon=self.satochip_unpaired_icon)
    def show_success(self, msg):
        sg.popup('Satochip-Bridge Success!', msg, icon=self.satochip_icon)
    def show_message(self, msg):
        sg.popup('Satochip-Bridge Notification', msg, icon=self.satochip_icon)
    def show_notification(self, title, msg):
        #logger.debug("START show_notification")
        self.tray.ShowMessage(title, msg, time=100000)
    
    def ok_or_cancel_msg(self, msg):
        logger.debug('In ok_or_cancel_msg')
        layout = [[sg.Text(msg)],    
                        [sg.Button('Ok'), sg.Button('Cancel')]]   
        window = sg.Window('Satochip-Bridge: Confirmation required', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        return (event, values)
    
    def approve_action(self, question):
        logger.debug('In approve_action')
        layout = [[sg.Text(question)],    
                        [sg.Checkbox('Skip confirmation for this connection (not recommended)', key='skip_conf')], 
                        [sg.Button('Yes'), sg.Button('No')]]   
        window = sg.Window('Satochip-Bridge: Confirmation required', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        return (event, values)
        
    def yes_no_question(self, question):
        logger.debug('In yes_no_question')
        layout = [[sg.Text(question)],      
                        [sg.Button('Yes'), sg.Button('No')]]      
        #window = sg.Window('Satochip-Bridge: Confirmation required', layout, icon=SatochipBase64)    #NOK
        window = sg.Window('Satochip-Bridge: Confirmation required', layout, icon=self.satochip_icon)  #ok
        #window = sg.Window('Satochip-Bridge: Confirmation required', layout, icon="satochip.ico")    #ok
        event, value = window.read()    
        window.close()  
        del window
        
        #logger.debug("Type of event from getpass:"+str(type(event))+str(event))
        if event=='Yes':
            return True
        else: # 'No' or None
            return False
                
    def get_passphrase(self, msg): 
        logger.debug('In get_passphrase')
        layout = [[sg.Text(msg)],      
                         [sg.InputText(password_char='*', key='pin')],      
                         [sg.Submit(), sg.Cancel()]]      
        window = sg.Window('Satochip-Bridge: PIN required', layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        is_PIN= True if event=='Submit' else False 
        pin = values['pin']
        # logger.debug("Type of pin from getpass:"+str(type(pin)))
        # logger.debug("Type of event from getpass:"+str(type(event))+str(event))
        return (is_PIN, pin)
        
    def QRDialog(self, data, parent=None, title = "Satochip-Bridge: QR code", show_text=False, msg= ''):
        logger.debug('In QRDialog')
        import pyqrcode
        code = pyqrcode.create(data)
        image_as_str = code.png_as_base64_str(scale=5, quiet_zone=2) #string
        image_as_str= base64.b64decode(image_as_str) #bytes
        
        layout = [[sg.Image(data=image_as_str, tooltip=None, visible=True)],
                        #[sg.Text(msg)], # cannot select and copy
                        [sg.Multiline(msg, size=(35,3))],
                        [sg.Button('Ok'), sg.Button('Cancel'), sg.Button('Copy 2FA-secret to clipboard')]]     
        window = sg.Window(title, layout, icon=self.satochip_icon)    
        while True:
            event, values = window.read()    
            if event=='Ok' or event=='Cancel':
                break
            elif event=='Copy 2FA-secret to clipboard':
                try:
                    pyperclip.copy(data) 
                except:
                    self.client.request('show_error', 'Could not copy data to clipboard! \nPlease select data manually and right-click to copy')
                
        window.close()
        del window
        try:
            pyperclip.copy('') #purge 2FA from clipboard
        except: 
            pass
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        return (event, values)
    
    def reset_seed_dialog(self, msg):
        logger.debug('In reset_seed_dialog')
        layout = [[sg.Text(msg)],
                [sg.InputText(password_char='*', key='pin')], 
                #[sg.Checkbox('Also reset 2FA', key='reset_2FA')], 
                [sg.Button('Ok'), sg.Button('Cancel')]]
        window = sg.Window("Satochip-Bridge: Reset seed", layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        return (event, values)
    
    ### SEED Config ###
    def choose_seed_action(self):
        logger.debug('In choose_seed_action')
        layout = [[sg.Text("Do you want to create a new seed, or to restore a wallet using an existing seed?")],
                [sg.Radio('Create a new seed', 'radio1', key='create')], 
                [sg.Radio('I already have a seed', 'radio1', key='restore')], 
                [sg.Button('Cancel'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Create or restore seed", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'create': True, 'restore': False}
        return (event, values)
        
    def create_seed(self, seed):    
        logger.debug('In create_seed')
        warning1= ("Please save these 12 words on paper (order is important). \nThis seed will allow you to recover your wallet in case of computer failure.")
        warning2= ("WARNING:")
        warning3= ("*Never disclose your seed.\n*Never type it on a website.\n*Do not store it electronically.")
        
        layout = [[sg.Text("Your wallet generation seed is:")],
                #[sg.Text(seed)], 
                [sg.Multiline(seed, size=(40,4) )], 
                [sg.Checkbox('Extends this seed with custom words', key='use_passphrase')], 
                [sg.Text(warning1)],
                [sg.Text(warning2)],
                [sg.Text(warning3)],
                [sg.Button('Back'), sg.Button('Next'), sg.Button('Copy seed to clipboard')]]
        window = sg.Window("Satochip-Bridge: Create seed", layout, icon=self.satochip_icon)        
        while True:
            event, values = window.read()    
            if event=='Back' or event=='Next' :
                break
            elif event=='Copy seed to clipboard':
                try:
                    pyperclip.copy(seed)
                except:
                    self.client.request('show_error', 'Could not copy data to clipboard! \nPlease select data manually and right-click to copy')
        window.close()
        del window
        
        try:
            pyperclip.copy('') #purge seed from clipboard
        except: 
            pass
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'use_passphrase': False}
        return (event, values)
        
    def request_passphrase(self):
        logger.debug('In request_passphrase')
        info1= ("You may extend your seed with custom words.\nYour seed extension must be saved together with your seed.")
        info2=("Note that this is NOT your encryption password.\nIf you do not know what this is, leave this field empty.")
        layout = [[sg.Text("Seed extension")],
                [sg.Text(info1)], 
                [sg.InputText(key='passphrase')], 
                [sg.Text(info2)],
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Seed extension", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'passphrase': 'toto'}
        return (event, values)
        
        
    def confirm_seed(self):
        logger.debug('In confirm_seed')
        info1= ("Your seed is important! If you lose your seed, your money will be \npermanently lost. To make sure that you have properly saved your \nseed, please retype it here:")
        layout = [[sg.Text("Confirm seed")],
                [sg.Text(info1)], 
                [sg.InputText(key='seed_confirm')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Confirm seed", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'seed_confirm': 'AA ZZ'}
        return (event, values)
        
    def confirm_passphrase(self):
        logger.debug('In confirm_passphrase')
        info1= ("Your seed extension must be saved together with your seed.\nPlease type it here.")
        layout = [[sg.Text("Confirm seed extension")],
                [sg.Text(info1)], 
                [sg.InputText(key='passphrase_confirm')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Confirm seed extension", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        
        logger.debug("Event:"+str(type(event))+str(event))
        logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'seed_confirm': 'AA ZZ'}
        return (event, values)
        
    def restore_from_seed(self):
        logger.debug('In restore_from_seed')
        from mnemonic import Mnemonic
        MNEMONIC = Mnemonic(language="english")
        
        info1= ("Please enter your BIP39 seed phrase in order to restore your wallet.")
        layout = [[sg.Text("Enter Seed")],
                [sg.Text(info1)], 
                [sg.InputText(key='seed')], 
                [sg.Checkbox('Extends this seed with custom words', key='use_passphrase')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Enter seed", layout, icon=self.satochip_icon)        
        while True:
            event, values = window.read()    
            if event=='Next' :
                if not MNEMONIC.check(values['seed']):# check that seed is valid
                    self.client.request('show_error', "Invalid BIP39 seed! Please type again!")
                else:
                    break            
            else: #  event=='Back'
                break
        window.close()
        del window
        
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        return (event, values)
    
    ### 2FA actions ###
    def choose_2FA_action(self):
        logger.debug('In choose_2FA_action')
        layout = [
                #[sg.Text("Do you want to create a new seed, or to restore a wallet using an existing seed?")],
                [sg.Button('Enable 2FA')], 
                [sg.Button('Reset 2FA')], 
                [sg.Button('Enable 2FA from 2FA-secret backup')], 
                [sg.Button('Reset 2FA from 2FA-secret backup')], 
                [sg.Button('Generate QR code from 2FA-secret backup')], 
                [sg.Button('Select 2FA server')], 
                [sg.Button('Cancel')],
        ]
        window = sg.Window("Satochip-Bridge: 2FA options", layout, icon=self.satochip_icon)        
        event, values = window.read()    
        window.close()
        del window
        return (event, values)
    
    def import_2FA_backup(self):
        logger.debug('In import_2FA_backup')
        layout = [
            [sg.Text("Enter your 2FA-secret backup (40-hex characters) below")],
            [sg.Text('Hex value: ', size=(10, 1)), sg.InputText(key='secret_2FA', size=(40, 1))],
            [sg.Text(size=(40,1), key='-OUTPUT-')],
            [sg.Submit(), sg.Cancel()],
        ] 
        window = sg.Window('Import 2FA-secret backup', layout, icon=self.satochip_icon)  #ok
        #event, values=None, None
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Submit':    
                try:
                    secret_2FA= values['secret_2FA']
                    int(secret_2FA, 16) # check if correct hex
                    secret_2FA= secret_2FA[secret_2FA.startswith("0x") and len("0x"):] #strip '0x' if need be
                    if len(secret_2FA) != 40:
                        raise ValueError(f"Wrong 2FA-secret size: {len(secret_2FA)}")
                    values['secret_2FA']= secret_2FA
                    break
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex)) #update('Error: seed should be an hex string with the correct length!')
                
        window.close()
        del window
        return event, values
    
    ### WalletConnect actions ###
    def wallet_connect_create_new_session(self):
        logger.debug('In wallet_connect_create_new_session')
        layout = [
            [sg.Text("Enter the WalletConnect URL below: ")],
            [sg.Multiline(key='wc_url', size=(60, 5))],
            [sg.Text("Select the address: "), sg.InputText(default_text = "m/44'/60'/0'/0", key='bip32_path', size=(40, 1))], # TODO: pregenerate list of address instead of path
            [sg.Text(size=(40,1), key='-OUTPUT-')],
            [sg.Submit(), sg.Cancel()],
        ] 
        # TODO: get BIP32 path?
        window = sg.Window('Create new WalletConnect session', layout, icon=self.satochip_icon)  #ok
        
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Submit':    
                # check bip32 path
                try:
                    bip32_path= values['bip32_path']
                    check= re.match("^(m/)?(\d+'?/)*\d+'?$", bip32_path); # https://stackoverflow.com/questions/61554569/bip32-derivepath-different-privatekey-in-nodejs-and-dartflutter-same-mnemonic
                    if check is None:
                        raise ValueError(f"Wrong bip32 path format!") 
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex))
                    continue
                # check url
                try:
                    wc_url= values['wc_url']
                    wc_session= WCSession.from_uri(wc_url)
                    values['wc_url']= wc_url
                    values['wc_session']= wc_session
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex))
                    continue
                # if all goes well
                break
        window.close()
        del window
        return event, values
    
    def wallet_connect_close_session(self):
        if self.wc_callback.wc_client is not None:
            try:
                wc_remote_peer_meta= self.wc_callback.wc_remote_peer_meta
                event_close, values_close= self.wallet_connect_close_session_dialog(wc_remote_peer_meta)
                if event_close== "Submit":
                    self.wc_callback.killSession()
                    self.show_notification("Notification", "WalletConnect session closed successfully!")
                else:
                    self.show_notification("Notification", "Action cancelled by user!")
            except Exception as ex:
                logger.warning("Exception while closing existing session: "+ str(ex))
                self.show_notification("Notification", f"Exception while closing existing session: {ex}")
                self.wc_callback.wc_client= None # force closing
    
    def wallet_connect_close_session_dialog(self, wc_peer_meta: WCPeerMeta):
        logger.debug('In wallet_connect_close_session_dialog')
        layout_meta= self.wallet_connect_generate_layout_from_meta(wc_peer_meta)
        layout = [
            [sg.Text("A WalletConnect session is already active")],
            layout_meta,
            [sg.Button('Close this session', key="Submit"), sg.Cancel()],
        ] 
        window = sg.Window('Close WalletConnect session?', layout, icon=self.satochip_icon) 
        event, values = window.read()    
        window.close()
        del window
        return (event, values)
    
    def wallet_connect_approve_new_session(self, wc_peer_meta: WCPeerMeta):
        logger.debug('In wallet_connect_approve_new_session')
        
        layout_meta= self.wallet_connect_generate_layout_from_meta(wc_peer_meta)
        layout = [
            [sg.Text("An app wants to connect to your your Satochip via WalletConnect!")],
            [sg.Text("The app provided the following info:")],
            layout_meta,
            [sg.Button('Approve connection', key="Submit"), sg.Cancel()],
        ] 
        window = sg.Window('Approve new WalletConnect session?', layout, icon=self.satochip_icon) 
        event, values = window.read()    
        window.close()
        del window
        return (event, values)
    
    def wallet_connect_approve_action(self, action, address, data):
        logger.debug('In wallet_connect_approve_action')
        layout = [
            [sg.Text("An app wants to perform the following on your Satochip via WalletConnect:")],    
            [sg.Text(f"Action: {action}")],    
            [sg.Text(f"Address: {address}")],    
            [sg.Text(f"Details:")],    
            [sg.Multiline(data, size=(60,6) )],
            #[sg.Text(f"Approve this action?")],    
            [sg.Button("Approve", key='Yes'), sg.Button("Reject", key='No')],
        ]   
        window = sg.Window('WalletConnect: confirmation required', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        return (event, values)
    
    def wallet_connect_generate_layout_from_meta(self, wc_peer_meta: WCPeerMeta):
        logger.debug('In wallet_connect_generate_layout_from_meta')
        name = wc_peer_meta.name
        url = wc_peer_meta.url
        description = wc_peer_meta.description
        icons = wc_peer_meta.icons
        # get icon image
        icon_available= False
        try:
            icon_url= icons[0]
            import requests
            from PIL import Image
            from io import BytesIO
            size = (128, 128)
            response = requests.get(icon_url)
            if response.status_code == 200:
                img = Image.open(BytesIO(response.content))
                img.thumbnail(size)
                #img.show() #debug open external viewer
                bio = BytesIO()
                img.save(bio, format="PNG")
                icon_raw= bio.getvalue()
                icon_available= True
        except Exception as ex:
            logger.debug(f'Exception while fetching image from url: {nft_image_url}  Exception: {ex}')
        # icon layout
        if icon_available:
            icon_layout = [
                [sg.Image(data=icon_raw, pad=(5,5))], 
            ] 
        else:
            icon_layout = [
                [sg.Text("(Unable to display icon!)")],
            ] 
        # layout
        info_layout = [
            [sg.Text(f"App name: {name}")],
            [sg.Text(f"Website: {url}")],
            [sg.Text(f"Description: {description}")],
        ] 
        layout = [sg.Column(info_layout), sg.Column(icon_layout)]
        return layout
        
    # communicate with other threads through queues
    def reply(self):    
        
        while not self.client.queue_request.empty(): 
            #logger.debug('Debug: check QUEUE NOT EMPTY')
            (request_type, args)= self.client.queue_request.get()
            logger.debug("Request in queue:" + str(request_type))
            for arg in args: 
                logger.debug("Next argument through *args :" + str(arg)) 
            
            method_to_call = getattr(self, request_type)
            #logger.debug('Type of method_to_call: '+ str(type(method_to_call)))
            #logger.debug('method_to_call: '+ str(method_to_call))
            
            reply = method_to_call(*args)
            self.client.queue_reply.put((request_type, reply))
                    
    # system tray   
    def system_tray(self, card_present):
        logger.debug('In system_tray')
        self.menu_def = ['BLANK', ['&Setup new Satochip', '&Change PIN', '&Reset seed', '&2FA options', '&Start WalletConnect', '&Stop WalletConnect', '&About', '&Quit']]
        if card_present:
            self.tray = sg.SystemTray(menu=self.menu_def, filename=self.satochip_icon) 
        else:
            self.tray = sg.SystemTray(menu=self.menu_def, filename=self.satochip_unpaired_icon) 

        while True:
            menu_item = self.tray.Read(timeout=1)
            if menu_item != '__TIMEOUT__':
                logger.debug('Menu item: '+menu_item) 
            
            ## Setup new Satochip ##
            if menu_item== 'Setup new Satochip':
                self.client.card_init_connect()
            
            ## Change PIN ##
            elif menu_item== 'Change PIN':
                msg_oldpin= ("Enter the current PIN for your Satochip:")
                msg_newpin= ("Enter a new PIN for your Satochip:")
                msg_confirm= ("Please confirm the new PIN for your Satochip:")
                msg_error= ("The PIN values do not match! Please type PIN again!")
                msg_cancel= ("PIN change cancelled!")
                (is_PIN, oldpin, newpin)= self.client.PIN_change_dialog(msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel)
                if not is_PIN:
                    continue
                else: 
                    oldpin= list(oldpin)    
                    newpin= list(newpin)  
                    (response, sw1, sw2)= self.client.cc.card_change_PIN(0, oldpin, newpin)
                    if (sw1==0x90 and sw2==0x00):
                        msg= ("PIN changed successfully!")
                        self.show_success(msg)
                    else:
                        msg= (f"Failed to change PIN with error code: {hex(sw1)}{hex(sw2)}")
                        self.show_error(msg)
             
            ## Reset seed ##
            elif menu_item== 'Reset seed':
                msg = ''.join([
                        ("WARNING!\n"),
                        ("You are about to reset the seed of your Satochip. This process is irreversible!\n"),
                        ("Please be sure that your wallet is empty and that you have a backup of the seed as a precaution.\n\n"),
                        ("To proceed, enter the PIN for your Satochip:")
                    ])
                (event, values)= self.reset_seed_dialog(msg)
                if event== 'Cancel':
                    msg= ("Seed reset cancelled!")
                    self.show_message(msg)
                    continue
                
                pin= values['pin']
                #reset_2FA= values['reset_2FA']
                pin= list(pin.encode('utf8'))
                
                # if 2FA is enabled, get challenge-response
                hmac=[]
                try: # todo: check if is_seeded
                    self.client.cc.card_bip32_get_authentikey()
                    self.client.cc.is_seeded=True
                except UninitializedSeedError:
                    self.client.cc.is_seeded=False
                if self.client.cc.needs_2FA and self.client.cc.is_seeded: 
                    # challenge based on authentikey
                    authentikeyx= bytearray(self.client.cc.parser.authentikey_coordx).hex()
                    
                    # format & encrypt msg
                    import json
                    msg= {'action':"reset_seed", 'authentikeyx':authentikeyx}
                    msg=  json.dumps(msg)
                    (id_2FA, msg_out)= self.client.cc.card_crypt_transaction_2FA(msg, True)
                    d={}
                    d['msg_encrypt']= msg_out
                    d['id_2FA']= id_2FA
                    # logger.debug("encrypted message: "+msg_out)
                    
                    #do challenge-response with 2FA device...
                    self.show_message('2FA request sent! Approve or reject request on your second device.')
                    try:
                        # get current server from config
                        if os.path.isfile('satochip_bridge.ini'):      
                            config = ConfigParser()
                            config.read('satochip_bridge.ini')
                            server_default= config.get('2FA', 'server_default')
                        else:
                            server_default= SERVER_LIST[0] # no config file => default server
                        # send request to server
                        Satochip2FA.do_challenge_response(d, server_default)
                        # decrypt and parse reply to extract challenge response
                        reply_encrypt= d['reply_encrypt']
                        reply_decrypt= self.client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
                    except Exception as e:
                        self.show_error("No response received from 2FA...")
                        continue
                    logger.debug("challenge:response= "+ reply_decrypt)
                    reply_decrypt= reply_decrypt.split(":")
                    chalresponse=reply_decrypt[1]
                    hmac= list(bytes.fromhex(chalresponse))
                
                # send request 
                (response, sw1, sw2) = self.client.cc.card_reset_seed(pin, hmac)
                if (sw1==0x90 and sw2==0x00):
                    msg= ("Seed reset successfully!\nYou can launch the wizard to setup your Satochip")
                    self.show_success(msg)
                else:
                    msg= (f"Failed to reset seed with error code: {hex(sw1)}{hex(sw2)}")
                    self.show_error(msg)
                
            ## 2FA options ##
            elif menu_item== '2FA options':
                (event, values)= self.choose_2FA_action()
                if event== 'Cancel':
                    continue
                elif event== 'Enable 2FA':
                    self.client.init_2FA()
                    continue
                elif event== 'Enable 2FA from 2FA-secret backup':
                    self.client.init_2FA(from_backup=True)
                    continue
                elif event== 'Reset 2FA':
                    if self.client.cc.needs_2FA:     
                        # challenge based on ID_2FA
                        # format & encrypt msg
                        import json
                        msg= {'action':"reset_2FA"}
                        msg=  json.dumps(msg)
                        (id_2FA, msg_out)= self.client.cc.card_crypt_transaction_2FA(msg, True)
                        d={}
                        d['msg_encrypt']= msg_out
                        d['id_2FA']= id_2FA
                        
                        #do challenge-response with 2FA device...
                        self.show_message('2FA request sent! Approve or reject request on your second device.')
                        # decrypt and parse reply to extract challenge response
                        try: 
                            # get current server from config
                            if os.path.isfile('satochip_bridge.ini'):  
                                config = ConfigParser()
                                config.read('satochip_bridge.ini')
                                server_default= config.get('2FA', 'server_default')
                            else:
                                server_default= SERVER_LIST[0] # no config file => default server
                            # send challenge and decrypt response
                            Satochip2FA.do_challenge_response(d, server_default)
                            reply_encrypt= d['reply_encrypt']
                            reply_decrypt= self.client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
                        except Exception as e:
                            self.show_error("No response received from 2FA...")
                            continue
                        logger.debug("challenge:response= "+ reply_decrypt)
                        reply_decrypt= reply_decrypt.split(":")
                        chalresponse=reply_decrypt[1]
                        hmac= list(bytes.fromhex(chalresponse))
                        
                        # send request 
                        (response, sw1, sw2) = self.client.cc.card_reset_2FA_key(hmac)
                        if (sw1==0x90 and sw2==0x00):
                            self.client.cc.needs_2FA= False
                            msg= ("2FA reset successfully!")
                            self.show_success(msg)
                        else:
                            msg= (f"Failed to reset 2FA with error code: {hex(sw1)}{hex(sw2)}")
                            self.show_error(msg)    
                    else:
                        self.show_error(f"Aborted: 2FA is not enabled on this device!")    
                    continue
                
                elif event== 'Reset 2FA from 2FA-secret backup':
                    # useful to deactivate 2FA if 2FA-app is unavailable
                    if self.client.cc.needs_2FA:     
                        import hmac
                        from hashlib import sha1
                        (events2, values2)= self.import_2FA_backup()
                        secret_2FA_hex= values2['secret_2FA']
                        secret_2FA_bytes=bytes.fromhex(secret_2FA_hex)
                        
                        # reset seed first (required for applet v<=0.11)
                        # todo: check if really necessary to reset seed?
                        try: # todo: check if is_seeded
                            self.client.cc.card_bip32_get_authentikey()
                            self.client.cc.is_seeded=True
                        except UninitializedSeedError:
                            self.client.cc.is_seeded=False
                        
                        if self.client.cc.is_seeded:
                            msg = ''.join([
                                    ("WARNING!\n"),
                                    ("You are about to reset the seed of your Satochip. This process is irreversible!\n"),
                                    ("Please be sure that your wallet is empty and that you have a backup of the seed as a precaution.\n\n"),
                                    ("To proceed, enter the PIN for your Satochip:")
                                ])
                            (event3, values3)= self.reset_seed_dialog(msg)
                            if event3== 'Cancel':
                                msg= ("Seed reset cancelled!")
                                self.show_message(msg)
                                continue
                            pin= values3['pin']
                            pin= list(pin.encode('utf8'))
                            # challenge
                            authentikeyx= bytearray(self.client.cc.parser.authentikey_coordx).hex()
                            challenge= authentikeyx + 32*'FF'
                            mac = hmac.new(secret_2FA_bytes, bytes.fromhex(challenge), sha1)
                            chalresponse_hex= mac.hexdigest()
                            chalresponse_list= list(bytes.fromhex(chalresponse_hex))
                            # send request 
                            (response, sw1, sw2) = self.client.cc.card_reset_seed(pin, chalresponse_list)
                            if (sw1==0x90 and sw2==0x00):
                                msg= ("Seed reset successfully!")
                                self.show_success(msg)
                            else:
                                msg= (f"Failed to reset seed with error code: {hex(sw1)}{hex(sw2)}")
                                self.show_error(msg)
                                continue
                            
                        # reset 2FA
                        #compute id_2FA_20b
                        mac = hmac.new(secret_2FA_bytes, "id_2FA".encode('utf-8'), sha1)
                        id_2FA_20b= mac.hexdigest()
                        #compute challenge & response
                        challenge= id_2FA_20b + 44*'AA'
                        mac = hmac.new(secret_2FA_bytes, bytes.fromhex(challenge), sha1)
                        chalresponse_hex= mac.hexdigest()
                        chalresponse_list= list(bytes.fromhex(chalresponse_hex))
                        # send request 
                        (response, sw1, sw2) = self.client.cc.card_reset_2FA_key(chalresponse_list)
                        if (sw1==0x90 and sw2==0x00):
                            self.client.cc.needs_2FA= False
                            msg= ("2FA reset successfully!")
                            self.show_success(msg)
                        else:
                            msg= (f"Failed to reset 2FA with error code: {hex(sw1)}{hex(sw2)}")
                            self.show_error(msg)    
                    else:
                        self.show_error(f"Aborted: 2FA is not enabled on this device!")    
                    continue
                 
                elif event== 'Generate QR code from 2FA-secret backup':
                    (events2, values2)= self.import_2FA_backup()
                    secret_2FA_hex= values2['secret_2FA']
                    msg= 'Scan this QR code on your second device \nand securely save a backup of this 2FA-secret: \n'+secret_2FA_hex
                    (event3, values3)= self.QRDialog(secret_2FA_hex, None, "Satochip-Bridge: QR Code", True, msg)
                    continue
                    
                elif event== 'Select 2FA server':            
                    # get current server from config
                    try:
                        if os.path.isfile('satochip_bridge.ini'):  
                            config = ConfigParser()
                            config.read('satochip_bridge.ini')
                            server_default= config.get('2FA', 'server_default')
                        else:
                            # no config file => default server
                            server_default= SERVER_LIST[0]
                    except Exception as e:
                        logger.warning("Exception while fetching 2FA server url: "+ str(e))
                        server_default= SERVER_LIST[0]
                    # get list of server
                    layout = [
                            [sg.Text("Select the 2FA server from the list below:")],
                            [sg.InputCombo(SERVER_LIST, size=(40, 1), default_value = server_default, key='server_list' )],
                            [sg.Text("Current server: " + server_default)],
                            [sg.Submit(), sg.Cancel()], 
                    ]
                    window = sg.Window("Satochip-Bridge: select 2FA server", layout, icon=self.satochip_icon)        
                    event, values = window.read()    
                    window.close()
                    del window
                    
                    # update config
                    if (event=='Submit'):
                        server_new = values['server_list']
                        if server_new != server_default:
                            try: 
                                # update config
                                config = ConfigParser()
                                config.read('satochip_bridge.ini')
                                if config.has_section('2FA') is False:
                                    config.add_section('2FA')
                                config.set('2FA', 'server_default', server_new)
                                with open('satochip_bridge.ini', 'w') as f:
                                    config.write(f)
                            except Exception as e:
                                logger.warning("Exception while saving 2FA server url to config file: "+ str(e))
                                self.show_error("Exception while saving 2FA server url to config file: "+ str(e))
                    else:
                        continue
                    
                else:   
                    continue
            
            elif menu_item== 'Start WalletConnect':
                if self.wc_callback.sato_client is None: # on the first use, sato_client may not be initialized
                    self.wc_callback.sato_client= self.client
                # if there is an existing session
                if self.wc_callback.wc_client is not None:
                    self.wallet_connect_close_session()
                # create new session   
                event_create, values_create = self.wallet_connect_create_new_session()
                if (event_create=='Submit'):
                    wc_session= values_create['wc_session']
                    bip32_path= values_create['bip32_path']
                    self.wc_callback.wallet_connect_initiate_session(wc_session, bip32_path) # todo: create callaback in satochipBridge and add ref in handler directly?
                else:
                    continue
            
            elif menu_item== 'Stop WalletConnect':
                if self.wc_callback.wc_client is not None:
                    self.wallet_connect_close_session()
                else:
                    self.show_notification("Notification", "No WalletConnect session open!")
                continue
            
            ## About ##
            elif menu_item== 'About':
                #copyright
                msg_copyright= ''.join([ '(c)2020 - Satochip by Toporin - https://github.com/Toporin/ \n',
                                                        "This program is licensed under the GNU Lesser General Public License v3.0 \n",
                                                        "This software is provided 'as-is', without any express or implied warranty.\n",
                                                        "In no event will the authors be held liable for any damages arising from \n"
                                                        "the use of this software."])
                #sw version
                # v_supported= (CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION
                # sw_rel= str(CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION) +'.'+ str(CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION)
                v_supported= (SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+SATOCHIP_PROTOCOL_MINOR_VERSION
                sw_rel= str(SATOCHIP_PROTOCOL_MAJOR_VERSION) +'.'+ str(SATOCHIP_PROTOCOL_MINOR_VERSION)
                fw_rel= "N/A"
                is_seeded= "N/A"
                needs_2FA= "N/A"
                needs_SC= "N/A"
                msg_status= ("Card is not initialized! \nClick on 'Setup new Satochip' in the menu to start configuration.")
                    
                (response, sw1, sw2, status)=self.client.cc.card_get_status()
                if (sw1==0x90 and sw2==0x00):
                    #hw version
                    v_applet= (status["protocol_major_version"]<<8)+status["protocol_minor_version"] 
                    fw_rel= str(status["protocol_major_version"]) +'.'+ str(status["protocol_minor_version"] )
                    # status
                    if (v_supported<v_applet):
                        msg_status=('The version of your Satochip is higher than supported. \nYou should update Satochip-Bridge!')
                    else:
                        msg_status= 'Satochip-Bridge is up-to-date'
                    # needs2FA?
                    if len(response)>=9 and response[8]==0X01: 
                        needs_2FA= "yes"
                    elif len(response)>=9 and response[8]==0X00: 
                        needs_2FA= "no"
                    else:
                        needs_2FA= "unknown"
                    #is_seeded?
                    if len(response) >=10:
                        is_seeded="yes" if status["is_seeded"] else "no" 
                    else: #for earlier versions
                        try: 
                            self.client.cc.card_bip32_get_authentikey()
                            is_seeded="yes"
                        except UninitializedSeedError:
                            is_seeded="no"
                        except Exception:
                            is_seeded="unknown"    
                    # secure channel
                    if status["needs_secure_channel"]:
                        needs_SC= "yes"
                    else:
                        needs_SC= "no"
                else:
                    msg_status= 'No card found! please insert card!'
                    
                frame_layout1= [[sg.Text('Supported Version: ', size=(20, 1)), sg.Text(sw_rel)],
                                            [sg.Text('Firmware Version: ', size=(20, 1)), sg.Text(fw_rel)],
                                            [sg.Text('Wallet is seeded: ', size=(20, 1)), sg.Text(is_seeded)],
                                            [sg.Text('Requires 2FA: ', size=(20, 1)), sg.Text(needs_2FA)],
                                            [sg.Text('Uses Secure Channel: ', size=(20, 1)), sg.Text(needs_SC)]]
                frame_layout2= [[sg.Text('Satochip-Bridge version: ', size=(20, 1)), sg.Text(SATOCHIP_BRIDGE_VERSION)],
                                            [sg.Text('Pysatochip version: ', size=(20, 1)), sg.Text(PYSATOCHIP_VERSION)],
                                            [sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)]]
                frame_layout3= [[sg.Text(msg_copyright, justification='center', relief=sg.RELIEF_SUNKEN)]]
                layout = [[sg.Frame('Satochip', frame_layout1, font='Any 12', title_color='blue')],
                              [sg.Frame('Satochip-Bridge status', frame_layout2, font='Any 12', title_color='blue')],
                              [sg.Frame('About Satochip-Bridge', frame_layout3, font='Any 12', title_color='blue')],
                              [sg.Button('Ok')]]
                
                window = sg.Window('Satochip-Bridge: About', layout, icon=self.satochip_icon)    
                event, value = window.read()    
                window.close()  
                del window
                continue
             
            ## Quit ##
            elif menu_item in (None, 'Quit'):
                # close any existing WalletConnect session
                if self.wc_callback.wc_client is not None:
                    try:
                        self.wc_callback.killSession()
                    except Exception as ex:
                        logger.warning("Exception while closing existing session: "+ str(ex))
                # exit infinite loop
                break
                            
            # check for handle requests from client through the queue
            self.reply()
         
        # exit after leaving the loop
        #sys.exit() # does not finish background thread
        os._exit(0) # kill background thread but doesn't let the interpreter do any cleanup before the process dies