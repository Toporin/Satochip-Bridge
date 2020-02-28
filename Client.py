#import PySimpleGUI as sg   
import PySimpleGUIQt as sg     
import getpass
import pyperclip

#import pystray
#from PIL import Image
#from PIL import Image, ImageDraw

class Client:

    def __init__(self, plugin, handler):
        self.handler = handler
    
    def notify_handler(self, request_type, ):
        
    
    def PIN_dialog(self, msg):
        while True:
            password = self.handler.get_passphrase(msg)
            if password is None:
                 raise RuntimeError(('Device cannot be unlocked without PIN code!'))
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
            (is_PIN, pin_confirm)= self.PIN_dialog(msg_confirm)
            if (pin != pin_confirm):
                self.handler.show_error(msg_error) 
            else:
                return (is_PIN, pin)
        
    
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
        else:
            print("Card disconnected!")

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
        
        #Image(filename=None, data=None, background_color=None, size=(None, None), pad=None, key=None,
        #    tooltip=None, right_click_menu=None, visible=True, enable_events=False, metadata=None)

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
        
    ####
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
                (event, values)= self.choose_seed_action()
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
                
                (event, values)= self.create_seed(mnemonic)
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
                (event, values)= self.request_passphrase()
                if (event=='Next'):
                    passphrase= values['passphrase']
                    if (needs_confirm):
                        state= 'state_confirm_seed'
                    else:
                       break #finished
                else: #Back
                    state= 'state_choose_seed_action'
                
            elif (state=='state_confirm_seed'):               
                (event, values)= self.confirm_seed()
                mnemonic_confirm= values['seed_confirm']
                if (event=='Next') and (mnemonic== mnemonic_confirm):
                    if (use_passphrase):
                        state= 'state_confirm_passphrase'
                    else:
                        break #finish!
                elif (event=='Next') and (mnemonic!= mnemonic_confirm):
                    self.show_error('Seed mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
                    
            elif (state=='state_confirm_passphrase'):            
                (event, values)= self.confirm_passphrase()
                passphrase_confirm= values['passphrase_confirm']
                if (event=='Next') and (passphrase== passphrase_confirm):
                    break #finish!
                elif (event=='Next') and (passphrase!= passphrase_confirm):
                    self.show_error('Passphrase mismatch!')
                    state= 'state_choose_seed_action'
                else:
                    state= 'state_choose_seed_action'
            
            elif (state== 'state_restore_from_seed'):
                needs_confirm= False
                (event, values)= self.restore_from_seed()
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
                
        print('mnemonic: '+ str(mnemonic))
        print('passphrase: '+str(passphrase))
        passphrase='' if passphrase is None else passphrase
        seed= Mnemonic.to_seed(mnemonic, passphrase)
        print('seed: '+str(seed.hex()))
        
        return (mnemonic, passphrase, seed)
        
    # # System Tray
    # def add_system_tray(self):
        # print("System tray initialization!")
        # try: 
            # icon = pystray.Icon('test name')
            # width=32
            # height=32
            # color1=(128,128,128)
            # color2=(0,0,0)
            # # Generate an image
            # image = Image.new('RGB', (width, height), color1)
            # dc = ImageDraw.Draw(image)
            # dc.rectangle((width // 2, 0, width, height // 2), fill=color2)
            # dc.rectangle((0, height // 2, width // 2, height), fill=color2)

            # icon.icon = image
            # print("System tray A")
            # def setup(icon):
                # icon.visible = True
            # print("System tray C")
            # icon.run(setup)
            # print("System tray B")
            
        # except Exception as e:
                # print("In add_system_tray(): exception")
                # print(repr(e))

        # print("System tray init done!")
        
    def system_tray(self):
        menu_def = ['&File', ['&Open', '&Save',['1', '2', ['a','b']], '&Properties', 'E&xit']]

        tray = sg.SystemTray(menu=menu_def, filename=r'satochip.png')

        while True:
            menu_item = tray.Read(timeout=1)
            print(menu_item)
            if menu_item in (None, 'Exit'):
                break