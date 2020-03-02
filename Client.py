#import PySimpleGUI as sg   
import PySimpleGUIQt as sg     
import getpass
import pyperclip
import threading
from queue import Queue 
import sys
import os

from Satochip2FA import Satochip2FA
from CardConnector import CardConnector
#from CardConnector.CardConnector import SATOCHIP_PROTOCOL_MAJOR_VERSION

class Client:

    def __init__(self, cc, handler):
        self.handler = handler
        self.handler.client= self
        self.queue_request= Queue()
        self.queue_reply= Queue()
        self.cc= None
    
    def create_system_tray(self, card_present):
        self.handler.system_tray(card_present)
    
    def request(self, request_type, *args):
        
        # bypass queue-based data exchange between main GUI thread and   
        # server thread when request comes directly from the main thread.
        if threading.current_thread() is threading.main_thread():
            print('IN MAIN THREAD!')
            method_to_call = getattr(self.handler, request_type)
            print('Type of method_to_call: '+ str(type(method_to_call)))
            print('method_to_call: '+ str(method_to_call))
            reply = method_to_call(*args)
            return reply 
        
        # we use a queue to exchange request between the server thread and the main (GUI) thread
        self.queue_request.put((request_type, args))
        print('IN SECOND THREAD!')
        while True: 
            # Get some data 
            (reply_type, reply)= self.queue_reply.get() 
            
            if (reply_type != request_type):
                #todo: clean the queues
                RuntimeError("Reply mismatch during GUI handler notification!")
            else:
                return reply
        
        
    def PIN_dialog(self, msg):
        while True:
            #password = self.handler.get_passphrase(msg)
            password = self.request('get_passphrase',msg)
            if password is None:
                 #raise RuntimeError(('Device cannot be unlocked without PIN code!'))
                 return (False, None)
            elif len(password) < 4:
                msg = ("PIN must have at least 4 characters.") + \
                      "\n\n" + ("Enter PIN:")
            elif len(password) > 64:
                msg = ("PIN must have less than 64 characters.") + \
                      "\n\n" + ("Enter PIN:")
            else:
                pin = password.encode('utf8')
                return (True, pin)
    
    def PIN_setup_dialog(self, msg, msg_confirm, msg_error):
        while(True):
            (is_PIN, pin)= self.PIN_dialog(msg)
            if not is_PIN:
                raise RuntimeError(('A PIN code is required to initialize the Satochip!'))
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if not is_PIN:
                raise RuntimeError(('A PIN confirmation is required to initialize the Satochip!'))
            if (pin != pin_confirm):
                #self.handler.show_error(msg_error) 
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
     
    def seed_wizard(self): 
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
                #(event, values)= self.handler.choose_seed_action()
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
                if not MNEMONIC.check(mnemonic):
                    raise ValueError("Invalid Mnemonic")
                
                #(event, values)= self.handler.create_seed(mnemonic)
                (event, values)= self.request('create_seed', mnemonic)
                if (event=='Next') and (values['use_passphrase'] is True):
                    use_passphrase= True
                    state= 'state_request_passphrase'
                elif (event=='Next') and not values['use_passphrase']:
                    use_passphrase= False
                    state= 'state_confirm_seed'
                else: #Back
                    state= 'state_choose_seed_action'
                    break
            
            elif (state=='state_request_passphrase'):                        
                #(event, values)= self.handler.request_passphrase()
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
                #(event, values)= self.handler.confirm_seed()
                (event, values)= self.request('confirm_seed')
                mnemonic_confirm= values['seed_confirm']
                if (event=='Next') and (mnemonic== mnemonic_confirm):
                    if (use_passphrase):
                        state= 'state_confirm_passphrase'
                    else:
                        break #finish!
                elif (event=='Next') and (mnemonic!= mnemonic_confirm):
                    #self.handler.show_error('Seed mismatch!')
                    self.request('show_error','Seed mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
                    
            elif (state=='state_confirm_passphrase'):            
                #(event, values)= self.handler.confirm_passphrase()
                (event, values)= self.request('confirm_passphrase')
                passphrase_confirm= values['passphrase_confirm']
                if (event=='Next') and (passphrase== passphrase_confirm):
                    break #finish!
                elif (event=='Next') and (passphrase!= passphrase_confirm):
                    #self.handler.show_error('Passphrase mismatch!')
                    self.request('show_error','Passphrase mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
            
            elif (state== 'state_restore_from_seed'):
                needs_confirm= False
                #(event, values)= self.handler.restore_from_seed()
                (event, values)= self.request('restore_from_seed')
                mnemonic= values['seed']
                use_passphrase= values['use_passphrase']
                #TODO: check if mnemonic is correct
                if (event=='Next') and use_passphrase:
                    state= 'state_request_passphrase'
                elif (event=='Next') and not use_passphrase:
                    break #finished!
                else: #Back
                    state= 'state_choose_seed_action'
            
            else:
                print('Error!')
                
        passphrase='' if passphrase is None else passphrase
        seed= Mnemonic.to_seed(mnemonic, passphrase)
        #print('mnemonic: '+ str(mnemonic))
        #print('passphrase: '+str(passphrase))
        #print('seed: '+str(seed.hex()))
        
        return (mnemonic, passphrase, seed)
    
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
        pin = getpass.getpass(msg) #getpass returns a string
        return pin
        
    def QRDialog(self, data, parent=None, title = '', show_text=False, msg= ''):
        print(msg)

class HandlerSimpleGUI:
    def __init__(self): 
        sg.theme('BluePurple')
        pass

    def update_status(self, isConnected):
        if (isConnected):
            print("Card connected!")
            self.tray.update(filename=r'satochip.png')
        else:
            print("Card disconnected!")
            self.tray.update(filename=r'satochip_unpaired.png')
            

    def show_error(self, msg):
        sg.popup('Satochip-Bridge: Error!', msg)
    
    def show_message(self, msg):
        sg.popup('Satochip-Bridge: Notification', msg)
    
    def yes_no_question(self, question):
               
        layout = [[sg.Text(question)],      
                        [sg.Button('Yes'), sg.Button('No')]]      
        window = sg.Window('Satochip-Bridge: Confirmation required', layout)    
        event, value = window.read()    
        window.close()  
        del window
        
        print("Type of event from getpass:"+str(type(event))+str(event))
        if event=='Yes':
            return True
        else: # 'No' or None
            return False
                
    def get_passphrase(self, msg): 
        
        layout = [[sg.Text(msg)],      
                         [sg.InputText(password_char='*', key='pin')],      
                         [sg.Submit(), sg.Cancel()]]      
        window = sg.Window('Satochip-Bridge: PIN required', layout)    
        event, values = window.read()    
        window.close()
        del window
        
        pin = values['pin']
        print("Type of pin from getpass:"+str(type(pin)))
        print("Type of event from getpass:"+str(type(event))+str(event))
        return pin
        
    def QRDialog(self, data, parent=None, title = "Satochip-Bridge: QR code", show_text=False, msg= ''):
        import pyqrcode
        code = pyqrcode.create(data)
        image_as_str = code.png_as_base64_str(scale=5, quiet_zone=2)

        layout = [[sg.Image(data=image_as_str, tooltip=None, visible=True)],
                        [sg.Text(msg)],
                        [sg.Button('Ok'), sg.Button('Cancel'), sg.Button('Copy 2FA-secret to clipboard')]]      
        window = sg.Window(title, layout)    
        while True:
            event, values = window.read()    
            if event=='Ok' or event=='Cancel':
                break
            elif event=='Copy 2FA-secret to clipboard':
                pyperclip.copy(data) 
                
        window.close()
        del window
        pyperclip.copy('') #purge 2FA from clipboard
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        return (event, values)
    
    def reset_seed_dialog(self, msg):
        layout = [[sg.Text(msg)],
                [sg.InputText(key='passphrase')], 
                [sg.Checkbox('Also reset 2FA', key='reset_2FA')], 
                [sg.Button('Ok'), sg.Button('Cancel')]]
        window = sg.Window("Satochip-Bridge: Reset seed", layout)    
        event, values = window.read()    
        window.close()
        del window
        
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Ok
        #Values:<class 'dict'>{'passphrase': 'toto', 'reset_2FA': False}
        return (event, values)
    
    ### SEED Config ###
    def choose_seed_action(self):
        
        layout = [[sg.Text("Do you want to create a new seed, or to restore a wallet using an existing seed?")],
                [sg.Radio('Create a new seed', 'radio1', key='create')], 
                [sg.Radio('I already have a seed', 'radio1', key='restore')], 
                [sg.Button('Cancel'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Create or restore seed", layout)        
        event, values = window.read()    
        window.close()
        del window
        
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'create': True, 'restore': False}
        return (event, values)
        
    def create_seed(self, seed):    
        
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
        window = sg.Window("Satochip-Bridge: Create seed", layout)        
        while True:
            event, values = window.read()    
            if event=='Back' or event=='Next' :
                break
            elif event=='Copy seed to clipboard':
                pyperclip.copy(seed)
        window.close()
        del window
        
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'use_passphrase': False}
        return (event, values)
        
    def request_passphrase(self):
        
        info1= ("You may extend your seed with custom words.\nYour seed extension must be saved together with your seed.")
        info2=("Note that this is NOT your encryption password.\nIf you do not know what this is, leave this field empty.")
        layout = [[sg.Text("Seed extension")],
                [sg.Text(info1)], 
                [sg.InputText(key='passphrase')], 
                [sg.Text(info2)],
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Seed extension", layout)        
        event, values = window.read()    
        window.close()
        del window
        
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'passphrase': 'toto'}
        return (event, values)
        
        
    def confirm_seed(self):
        pyperclip.copy('') #purge clipboard to ensure that seed is backuped
        info1= ("Your seed is important! If you lose your seed, your money will be \npermanently lost. To make sure that you have properly saved your \nseed, please retype it here:")
        layout = [[sg.Text("Confirm seed")],
                [sg.Text(info1)], 
                [sg.InputText(key='seed_confirm')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Confirm seed", layout)        
        event, values = window.read()    
        window.close()
        del window
        
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'seed_confirm': 'AA ZZ'}
        return (event, values)
        
    def confirm_passphrase(self):
        info1= ("Your seed extension must be saved together with your seed.\nPlease type it here.")
        layout = [[sg.Text("Confirm seed extension")],
                [sg.Text(info1)], 
                [sg.InputText(key='passphrase_confirm')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Confirm seed extension", layout)        
        event, values = window.read()    
        window.close()
        del window
        
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        #Event:<class 'str'>Next
        #Values:<class 'dict'>{'seed_confirm': 'AA ZZ'}
        return (event, values)
        
    def restore_from_seed(self):
        info1= ("Please enter your BIP39 seed phrase in order to restore your wallet.")
        layout = [[sg.Text("Enter Seed")],
                [sg.Text(info1)], 
                [sg.InputText(key='seed')], 
                [sg.Checkbox('Extends this seed with custom words', key='use_passphrase')], 
                [sg.Button('Back'), sg.Button('Next')]]
        window = sg.Window("Satochip-Bridge: Enter seed", layout)        
        event, values = window.read()    
        window.close()
        del window
        
        print("Event:"+str(type(event))+str(event))
        print("Values:"+str(type(values))+str(values))
        return (event, values)
    
    # communicate with other threads through queues
    def reply(self):    
    
        while not self.client.queue_request.empty(): 
            (request_type, args)= self.client.queue_request.get()
            print("Request in queue:", request_type)
            for arg in args: 
                print("Next argument through *args :", arg) 
            
            method_to_call = getattr(self, request_type)
            print('Type of method_to_call: '+ str(type(method_to_call)))
            print('method_to_call: '+ str(method_to_call))
            
            reply = method_to_call(*args)
            self.client.queue_reply.put((request_type, reply))
                
    # system tray   
    def system_tray(self, card_present):
        self.menu_def = ['BLANK', ['&Setup new Satochip', '&Change PIN', '&Reset seed', '&Enable 2FA', '&About', '&Quit']]
        
        if card_present:
            self.tray = sg.SystemTray(menu=self.menu_def, filename=r'satochip.png')
        else:
            self.tray = sg.SystemTray(menu=self.menu_def, filename=r'satochip_unpaired.png')

        while True:
            menu_item = self.tray.Read(timeout=1)
            if menu_item != '__TIMEOUT__':
                print(menu_item) 
            
            ## Setup new Satochip ##
            if menu_item== 'Setup new Satochip':
                self.client.cc.card_init_connect()
            
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
                        self.show_message(msg)
                    else:
                        msg= ("Failed to change PIN!")
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
                
                password= values['password']
                pin= list(password.encode('utf8'))
                
                # if 2FA is enabled, get challenge-response
                hmac=[]
                if (self.client.cc.needs_2FA==None):
                    (response, sw1, sw2, d)=self.client.cc.card_get_status()
                if self.client.cc.needs_2FA: 
                    #get authentikey 
                    self.client.cc.card_bip32_get_authentikey()
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
                    # _logger.info("encrypted message: "+msg_out)
                    
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
                    print("challenge:response= "+ reply_decrypt)
                    reply_decrypt= reply_decrypt.split(":")
                    chalresponse=reply_decrypt[1]
                    hmac= list(bytes.fromhex(chalresponse))
                
                # send request 
                (response, sw1, sw2) = self.client.cc.card_reset_seed(pin, hmac)
                if (sw1==0x90 and sw2==0x00):
                    msg= ("Seed reset successfully!\nYou should close this wallet and launch the wizard to generate a new wallet.")
                    self.show_message(msg)
                else:
                    msg= _(f"Failed to reset seed with error code: {hex(sw1)}{hex(sw2)}")
                    self.show_error(msg)
                continue
            
            ## Enable 2FA ##
            elif menu_item== 'Enable 2FA':
                self.client.cc.init_2FA()
                continue
             
            ## About ##
            elif menu_item== 'About':
                #copyright
                msg_copyright= ''.join([ '(c)2020 - Satochip by Toporin - https://github.com/Toporin/ \n',
                                                        "This program is licensed under the GNU Affero General Public License v3.0 \n",
                                                        "This software is provided 'as-is', without any express or implied warranty.\n",
                                                        "In no event will the authors be held liable for any damages arising from \n"
                                                        "the use of this software."])
                #sw version
                v_supported= (CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION
                sw_rel= str(CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION) +'.'+ str(CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION)
                fw_rel= "N/A"
                is_seeded= "N/A"
                needs_2FA= "N/A"
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
                    try: 
                        self.client.cc.card_bip32_get_authentikey()
                        is_seeded="yes"
                    except Exception:
                        is_seeded="no"
                
                
                frame_layout1= [[sg.Text('Supported Version: ', size=(20, 1)), sg.Text(sw_rel)],
                                            [sg.Text('Firmware Version: ', size=(20, 1)), sg.Text(fw_rel)],
                                            [sg.Text('Wallet is seeded: ', size=(20, 1)), sg.Text(is_seeded)],
                                            [sg.Text('Requires 2FA: ', size=(20, 1)), sg.Text(needs_2FA)]]
                frame_layout2= [[sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)]]
                frame_layout3= [[sg.Text(msg_copyright, justification='center', relief=sg.RELIEF_SUNKEN)]]
                  
                layout = [[sg.Frame('Satochip', frame_layout1, font='Any 12', title_color='blue')],
                              [sg.Frame('Satochip status', frame_layout2, font='Any 12', title_color='blue')],
                              [sg.Frame('About Satochip-Bridge', frame_layout3, font='Any 12', title_color='blue')],
                              [sg.Button('Ok')]]
                # layout = [ [sg.Text('Supported Version: ', size=(20, 1)), sg.Text(sw_rel)],
                                # [sg.Text('Firmware Version: ', size=(20, 1)), sg.Text(fw_rel)],
                                # [sg.Text('Wallet is seeded: ', size=(20, 1)), sg.Text(is_seeded)],
                                # [sg.Text('Requires 2FA: ', size=(20, 1)), sg.Text(needs_2FA)],
                                # [sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)],
                                # [sg.Text(msg_copyright, justification='center', relief=sg.RELIEF_SUNKEN)],
                                # [sg.Button('Ok')]]
                window = sg.Window('Satochip-Bridge: About', layout)    
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
                

            
            