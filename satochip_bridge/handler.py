#import PySimpleGUI as sg   
#import PySimpleGUIWx as sg 
import PySimpleGUIQt as sg 
import base64    
import getpass
import pyperclip
#import sys
import os
import logging
from queue import Queue 

from pysatochip.Satochip2FA import Satochip2FA
from pysatochip.CardConnector import CardConnector, UninitializedSeedError
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_PROTOCOL_VERSION

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
        self.pkg_dir = os.path.split(os.path.realpath(__file__))[0]
        logger.debug("PKGDIR= " + str(self.pkg_dir))
        self.satochip_icon= self.icon_path("satochip.png") #"satochip.png"
        self.satochip_unpaired_icon= self.icon_path("satochip_unpaired.png") #"satochip_unpaired.png"
         
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
    def show_notification(self,msg):
        #logger.debug("START show_notification")
        #self.tray.ShowMessage("Satochip-Bridge notification", msg, filename=self.satochip_icon, time=10000)
        self.tray.ShowMessage("Satochip-Bridge notification", msg, messageicon=sg.SYSTEM_TRAY_MESSAGE_ICON_INFORMATION, time=100000)
        #logger.debug("END show_notification")
    
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
                        [sg.Text(msg)],
                        [sg.Button('Ok'), sg.Button('Cancel'), sg.Button('Copy 2FA-secret to clipboard')]]     
        window = sg.Window(title, layout, icon=self.satochip_icon)    
        while True:
            event, values = window.read()    
            if event=='Ok' or event=='Cancel':
                break
            elif event=='Copy 2FA-secret to clipboard':
                pyperclip.copy(data) 
                
        window.close()
        del window
        pyperclip.copy('') #purge 2FA from clipboard
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        return (event, values)
    
    def reset_seed_dialog(self, msg):
        logger.debug('In reset_seed_dialog')
        layout = [[sg.Text(msg)],
                [sg.InputText(password_char='*', key='pin')], 
                [sg.Checkbox('Also reset 2FA', key='reset_2FA')], 
                [sg.Button('Ok'), sg.Button('Cancel')]]
        window = sg.Window("Satochip-Bridge: Reset seed", layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Ok
        #Values:<class 'dict'>{'passphrase': 'toto', 'reset_2FA': False}
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
                [sg.Text(seed)], 
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
                pyperclip.copy(seed)
        window.close()
        del window
        
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
        pyperclip.copy('') #purge clipboard to ensure that seed is backuped
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
        logger.debug('In confirm_passphrase')
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
            if event=='Back' or event=='Next' :
                if not MNEMONIC.check(values['seed']):# check that seed is valid
                    self.client.request('show_error', "Invalid BIP39 seed! Please type again!")
                else:
                    break            
        
        window.close()
        del window
        
        # logger.debug("Event:"+str(type(event))+str(event))
        # logger.debug("Values:"+str(type(values))+str(values))
        return (event, values)
    
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
        self.menu_def = ['BLANK', ['&Setup new Satochip', '&Change PIN', '&Reset seed', '&Enable 2FA', '&About', '&Quit']]
        
        if card_present:
            self.tray = sg.SystemTray(menu=self.menu_def, filename=self.satochip_icon) #self.tray = sg.SystemTray(menu=self.menu_def, filename=r'satochip.png')
        else:
            self.tray = sg.SystemTray(menu=self.menu_def, filename=self.satochip_unpaired_icon) #self.tray = sg.SystemTray(menu=self.menu_def, filename=r'satochip_unpaired.png')

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
                reset_2FA= values['reset_2FA']
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
                    Satochip2FA.do_challenge_response(d)
                    # decrypt and parse reply to extract challenge response
                    try: 
                        reply_encrypt= d['reply_encrypt']
                    except Exception as e:
                        self.show_error("No response received from 2FA...")
                        continue
                    reply_decrypt= self.client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
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
                
                # reset 2FA
                if reset_2FA and self.client.cc.needs_2FA:     
                    # challenge based on ID_2FA
                    # format & encrypt msg
                    import json
                    msg= {'action':"reset_2FA"}
                    msg=  json.dumps(msg)
                    (id_2FA, msg_out)= self.client.cc.card_crypt_transaction_2FA(msg, True)
                    d={}
                    d['msg_encrypt']= msg_out
                    d['id_2FA']= id_2FA
                    # _logger.info("encrypted message: "+msg_out)
                    
                    #do challenge-response with 2FA device...
                    self.client.handler.show_message('2FA request sent! Approve or reject request on your second device.')
                    Satochip2FA.do_challenge_response(d)
                    # decrypt and parse reply to extract challenge response
                    try: 
                        reply_encrypt= d['reply_encrypt']
                    except Exception as e:
                        self.show_error("No response received from 2FA...")
                    reply_decrypt= self.client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
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
            
            ## Enable 2FA ##
            elif menu_item== 'Enable 2FA':
                self.client.init_2FA()
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
                frame_layout2= [[sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)]]
                frame_layout3= [[sg.Text(msg_copyright, justification='center', relief=sg.RELIEF_SUNKEN)]]
                layout = [[sg.Frame('Satochip', frame_layout1, font='Any 12', title_color='blue')],
                              [sg.Frame('Satochip status', frame_layout2, font='Any 12', title_color='blue')],
                              [sg.Frame('About Satochip-Bridge', frame_layout3, font='Any 12', title_color='blue')],
                              [sg.Button('Ok')]]
                
                window = sg.Window('Satochip-Bridge: About', layout, icon=self.satochip_icon)    
                event, value = window.read()    
                window.close()  
                del window
                continue
             
            ## Quit ##
            elif menu_item in (None, 'Quit'):
                break
                            
            # check for handle requests from client through the queue
            self.reply()
         
        # exit after leaving the loop
        #sys.exit() # does not finish background thread
        os._exit(0) # kill background thread but doesn't let the interpreter do any cleanup before the process dies