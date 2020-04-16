from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.util import toHexString, toBytes
from smartcard.sw.SWExceptions import SWException

try:
    from JCconstants import JCconstants
    from TxParser import TxParser
    from ecc import ECPubkey, msg_magic
except Exception as e:
    print("Import exception")
    print(repr(e))
    from satochip_bridge.JCconstants import JCconstants
    from satochip_bridge.TxParser import TxParser
    from satochip_bridge.ecc import ECPubkey, msg_magic
    
import base64
import getpass
from os import urandom
#debug
import sys
import traceback

MSG_WARNING= ("Before you request bitcoins to be sent to addresses in this "
                    "wallet, ensure you can pair with your device, or that you have "
                    "its seed (and passphrase, if any).  Otherwise all bitcoins you "
                    "receive will be unspendable.")
                    
MSG_USE_2FA= ("Do you want to use 2-Factor-Authentication (2FA)?\n\n"
                "With 2FA, any transaction must be confirmed on a second device such as \n"
               "your smartphone. First you have to install the Satochip-2FA android app on \n"
               "google play. Then you have to pair your 2FA device with your Satochip \n"
               "by scanning the qr-code on the next screen. \n"
               "Warning: be sure to backup a copy of the qr-code in a safe place, \n"
               "in case you have to reinstall the app!")
               
# simple observer that will print on the console the card connection events.
class LogCardConnectionObserver(CardConnectionObserver):
    def update( self, cardconnection, ccevent ):
        if 'connect'==ccevent.type:
            print( 'connecting to', cardconnection.getReader())
        elif 'disconnect'==ccevent.type:
            print( 'disconnecting from',  cardconnection.getReader())
        elif 'command'==ccevent.type:
            if (ccevent.args[0][1] in (JCconstants.INS_SETUP, JCconstants.INS_SET_2FA_KEY,
                                        JCconstants.INS_BIP32_IMPORT_SEED, JCconstants.INS_BIP32_RESET_SEED,
                                        JCconstants.INS_CREATE_PIN, JCconstants.INS_VERIFY_PIN,
                                        JCconstants.INS_CHANGE_PIN, JCconstants.INS_UNBLOCK_PIN)):
                print(f"> {toHexString(ccevent.args[0][0:5])}{(len(ccevent.args[0])-5)*' *'}")
            else:
                print(f"> {toHexString(ccevent.args[0])}")
        elif 'response'==ccevent.type:
            if []==ccevent.args[0]:
                print( '< [] ', "%-2X %-2X" % tuple(ccevent.args[-2:]))
            else:
                print('< ', toHexString(ccevent.args[0]), "%-2X %-2X" % tuple(ccevent.args[-2:]))

# a card observer that detects inserted/removed cards and initiate connection
class RemovalObserver(CardObserver):
    """A simple card observer that is notified
    when cards are inserted/removed from the system and
    prints the list of cards
    """
    def __init__(self, cc):
        self.cc=cc
        self.observer = LogCardConnectionObserver() #ConsoleCardConnectionObserver()
            
    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            #TODO check ATR and check if more than 1 card?
            print("+Inserted: ", toHexString(card.atr))
            self.cc.card_present= True
            self.cc.cardservice= card
            self.cc.cardservice.connection = card.createConnection()
            self.cc.cardservice.connection.connect()
            self.cc.cardservice.connection.addObserver(self.observer)
            try:
                (response, sw1, sw2) = self.cc.card_select()
                if sw1!=0x90 or sw2!=0x00:
                    self.cc.card_disconnect()
                    break
                (response, sw1, sw2, status)= self.cc.card_get_status()
                if (sw1!=0x90 or sw2!=0x00) and (sw1!=0x9C or sw2!=0x04):
                    self.cc.card_disconnect()
                    break
            except Exception as exc:
                print("Error during connection:", repr(exc))
            if self.cc.client:
                self.cc.client.request('update_status',True)                
                
        for card in removedcards:
            print("-Removed: ", toHexString(card.atr))
            self.cc.card_disconnect()
            # self.cc.card_present= False
            # self.cc.pin= None #reset PIN
            # self.cc.pin_nbr= None
            # if self.cc.client:
                # self.cc.client.request('update_status',False)
                

class CardConnector:

    # Satochip supported version tuple
    # v0.4: getBIP32ExtendedKey also returns chaincode
    # v0.5: Support for Segwit transaction
    # v0.6: bip32 optimization: speed up computation during derivation of non-hardened child
    # v0.7: add 2-Factor-Authentication (2FA) support
    # v0.8: support seed reset and pin change
    # v0.9: patch message signing for alts
    # v0.10: sign tx hash
    SATOCHIP_PROTOCOL_MAJOR_VERSION=0
    SATOCHIP_PROTOCOL_MINOR_VERSION=10

    # define the apdus used in this script
    BYTE_AID= [0x53,0x61,0x74,0x6f,0x43,0x68,0x69,0x70] #SatoChip

    def __init__(self, parser, client=None):
        self.parser=parser
        self.client=client
        self.client.cc=self
        self.cardtype = AnyCardType() #TODO: specify ATR to ignore connection to wrong card types?
        self.needs_2FA = None
        self.is_seeded= None
        # cache PIN
        self.pin_nbr=None
        self.pin=None
        # cardservice
        self.cardservice= None #will be instantiated when a card is inserted
        try:
            self.cardrequest = CardRequest(timeout=0, cardType=self.cardtype)
            self.cardservice = self.cardrequest.waitforcard()
            self.card_present= True
        except CardRequestTimeoutException:
            self.card_present= False
        # monitor if a card is inserted or removed
        self.cardmonitor = CardMonitor()
        self.cardobserver = RemovalObserver(self)
        self.cardmonitor.addObserver(self.cardobserver)
        
    def card_transmit(self, apdu):
        if self.card_present:
            try:
                (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)
                if (sw1==0x9C) and (sw2==0x06):
                    (response, sw1, sw2)= self.card_verify_PIN()
                    (response, sw1, sw2)= self.cardservice.connection.transmit(apdu)
                return (response, sw1, sw2)
            except Exception as exc:
                print("Error during connection:", repr(exc), traceback.format_exc())
                self.client.request('show_error',"Error during connection:"+repr(exc))
                return ([], 0x00, 0x00)
        else:
            self.client.request('show_error','No Satochip found! Please insert card!')
            return ([], 0x00, 0x00)
            #TODO return errror or throw exception?
            
    def card_get_ATR(self):
        print('[CardConnector] card_get_ATR()')
        return self.cardservice.connection.getATR()
    
    def card_disconnect(self):
        print('[CardConnector] card_disconnect()')
        self.pin= None #reset PIN
        self.pin_nbr= None
        self.is_seeded= None
        self.needs_2FA = None
        self.card_present= False
        if self.cardservice:
            self.cardservice.connection.disconnect()
            self.cardservice= None
        if self.client:
            self.client.request('update_status',False)
        
    def get_sw12(self, sw1, sw2):
        return 16*sw1+sw2

    def card_select(self):
        print("[CardConnector] card_select")#debug
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08]
        apdu = SELECT + CardConnector.BYTE_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        return (response, sw1, sw2)

    def card_get_status(self):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_GET_STATUS
        p1= 0x00
        p2= 0x00
        le= 0x00
        apdu=[cla, ins, p1, p2, le]
        (response, sw1, sw2)= self.card_transmit(apdu)
        d={}
        if (sw1==0x90) and (sw2==0x00):
            d["protocol_major_version"]= response[0]
            d["protocol_minor_version"]= response[1]
            d["applet_major_version"]= response[2]
            d["applet_minor_version"]= response[3]
            if len(response) >=8:
                d["PIN0_remaining_tries"]= response[4]
                d["PUK0_remaining_tries"]= response[5]
                d["PIN1_remaining_tries"]= response[6]
                d["PUK1_remaining_tries"]= response[7]
                self.needs_2FA= d["needs2FA"]= False #default value
            if len(response) >=9:
                self.needs_2FA= d["needs2FA"]= False if response[8]==0X00 else True
            if len(response) >=10:
                self.is_seeded= d["is_seeded"]= False if response[9]==0X00 else True

        return (response, sw1, sw2, d)

    def card_setup(self,
                    pin_tries0, ublk_tries0, pin0, ublk0,
                    pin_tries1, ublk_tries1, pin1, ublk1,
                    memsize, memsize2,
                    create_object_ACL, create_key_ACL, create_pin_ACL,
                    option_flags=0, hmacsha160_key=None, amount_limit=0):

        # to do: check pin sizes < 256
        pin=[0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30] # default pin
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SETUP
        p1=0
        p2=0
        apdu=[cla, ins, p1, p2]

        # data=[pin_length(1) | pin |
        #       pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 |
        #       pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 |
        #       memsize(2) | memsize2(2) | ACL(3) |
        #       option_flags(2) | hmacsha160_key(20) | amount_limit(8)]
        if option_flags==0:
            optionsize= 0
        elif option_flags&0x8000==0x8000:
            optionsize= 30
        else:
            optionsize= 2
        le= 16+len(pin)+len(pin0)+len(pin1)+len(ublk0)+len(ublk1)+optionsize

        apdu+=[le]
        apdu+=[len(pin)]+pin
        apdu+=[pin_tries0,  ublk_tries0, len(pin0)] + pin0 + [len(ublk0)] + ublk0
        apdu+=[pin_tries1,  ublk_tries1, len(pin1)] + pin1 + [len(ublk1)] + ublk1
        apdu+=[memsize>>8, memsize&0x00ff, memsize2>>8, memsize2&0x00ff]
        apdu+=[create_object_ACL, create_key_ACL, create_pin_ACL]
        if option_flags!=0:
            apdu+=[option_flags>>8, option_flags&0x00ff]
            apdu+= hmacsha160_key
            for i in reversed(range(8)):
                apdu+=[(amount_limit>>(8*i))&0xff]

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)
        return (response, sw1, sw2)

    def card_bip32_import_seed(self, seed):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_IMPORT_SEED
        p1= len(seed)
        p2= 0x00
        le= len(seed)
        apdu=[cla, ins, p1, p2, le]+seed

        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        # compute authentikey pubkey and send to chip for future use
        authentikey= None
        if (sw1==0x90) and (sw2==0x00):
            authentikey= self.card_bip32_set_authentikey_pubkey(response)
            self.is_seeded= True
        return authentikey

    def card_reset_seed(self, pin, hmac=[]):
        cla= JCconstants.CardEdge_CLA
        ins= 0x77
        p1= len(pin)
        p2= 0x00
        le= len(pin)+len(hmac)
        apdu=[cla, ins, p1, p2, le]+pin+hmac

        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            self.is_seeded= False
        return (response, sw1, sw2)

    def card_bip32_get_authentikey(self):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_GET_AUTHENTIKEY
        p1= 0x00
        p2= 0x00
        le= 0x00
        apdu=[cla, ins, p1, p2, le]

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1==0x9c and sw2==0x14:
            print("card_bip32_get_authentikey(): Seed is not initialized => Raising error!")
            raise UninitializedSeedError("Satochip seed is not initialized!\n\n "+MSG_WARNING)
        if sw1==0x9c and sw2==0x04:
            print("card_bip32_get_authentikey(): Satochip is not initialized => Raising error!")
            raise UninitializedSeedError('Satochip is not initialized! You should create a new wallet!\n\n'+MSG_WARNING)
        # compute corresponding pubkey and send to chip for future use
        authentikey= None
        if (sw1==0x90) and (sw2==0x00):
            authentikey = self.card_bip32_set_authentikey_pubkey(response)
            self.is_seeded=True
        return authentikey

    ''' Allows to compute coordy of authentikey externally to optimize computation time-out
        coordy value is verified by the chip before being accepted '''
    def card_bip32_set_authentikey_pubkey(self, response):
        cla= JCconstants.CardEdge_CLA
        ins= 0x75
        p1= 0x00
        p2= 0x00

        authentikey= self.parser.parse_bip32_get_authentikey(response)
        if authentikey:
            coordy= authentikey.get_public_key_bytes(compressed=False)
            coordy= list(coordy[33:])
            data= response + [len(coordy)&0xFF00, len(coordy)&0x00FF] + coordy
            le= len(data)
            apdu=[cla, ins, p1, p2, le]+data
            (response, sw1, sw2) = self.card_transmit(apdu)
        return authentikey

    def card_bip32_get_extendedkey(self, path):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_BIP32_GET_EXTENDED_KEY
        p1= len(path)//4
        p2= 0x40 #option flags: 0x80:erase cache memory - 0x40: optimization for non-hardened child derivation
        le= len(path)
        apdu=[cla, ins, p1, p2, le]
        apdu+= path

        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        # send apdu
        while (True):
            (response, sw1, sw2) = self.card_transmit(apdu)

            # if there is no more memory available, erase cache...
            #if self.get_sw12(sw1,sw2)==JCconstants.SW_NO_MEMORY_LEFT:
            if (sw1==0x9C) and (sw2==0x01):
                print("card_bip32_get_extendedkey(): Reset memory...")#debugSatochip
                apdu[3]=apdu[3]^0x80
                response, sw1, sw2 = self.card_transmit(apdu)
                apdu[3]=apdu[3]&0x7f # reset the flag
            # other (unexpected) error
            if (sw1!=0x90) or (sw2!=0x00):
                raise UnexpectedSW12Error('Unexpected error code SW12='+hex(sw1)+" "+hex(sw2))
            # check for non-hardened child derivation optimization
            elif ( (response[32]&0x80)== 0x80):
                print("card_bip32_get_extendedkey(): Child Derivation optimization...")#debugSatochip
                (pubkey, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                coordy= pubkey.get_public_key_bytes(compressed=False)
                coordy= list(coordy[33:])
                authcoordy= self.parser.authentikey.get_public_key_bytes(compressed=False)
                authcoordy= list(authcoordy[33:])
                data= response+[len(coordy)&0xFF00, len(coordy)&0x00FF]+coordy
                apdu_opt= [cla, 0x74, 0x00, 0x00, len(data)]
                apdu_opt= apdu_opt+data
                response_opt, sw1_opt, sw2_opt = self.card_transmit(apdu_opt)
            #at this point, we have successfully received a response from the card
            else:
                (key, chaincode)= self.parser.parse_bip32_get_extendedkey(response)
                return (key, chaincode)

    def card_sign_message(self, keynbr, message, hmac=b''):
        if (type(message)==str):
            message = message.encode('utf8')

        # return signature as byte array
        # data is cut into chunks, each processed in a different APDU call
        chunk= 160 # max APDU data=255 => chunk<=255-(4+2)
        buffer_offset=0
        buffer_left=len(message)

        # CIPHER_INIT - no data processed
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_MESSAGE
        p1= keynbr # 0xff=>BIP32 otherwise STD
        p2= JCconstants.OP_INIT
        lc= 0x4
        apdu=[cla, ins, p1, p2, lc]
        for i in reversed(range(4)):
            apdu+= [((buffer_left>>(8*i)) & 0xff)]

        # send apdu
        (response, sw1, sw2) = self.card_transmit(apdu)

        # CIPHER PROCESS/UPDATE (optionnal)
        while buffer_left>chunk:
            #cla= JCconstants.CardEdge_CLA
            #ins= INS_COMPUTE_CRYPT
            #p1= key_nbr
            p2= JCconstants.OP_PROCESS
            le= 2+chunk
            apdu=[cla, ins, p1, p2, le]
            apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
            apdu+= message[buffer_offset:(buffer_offset+chunk)]
            buffer_offset+=chunk
            buffer_left-=chunk
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)

        # CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left #following while condition, buffer_left<=chunk
        #cla= JCconstants.CardEdge_CLA
        #ins= INS_COMPUTE_CRYPT
        #p1= key_nbr
        p2= JCconstants.OP_FINALIZE
        le= 2+chunk+ len(hmac)
        apdu=[cla, ins, p1, p2, le]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= message[buffer_offset:(buffer_offset+chunk)]+hmac
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)

    def card_sign_short_message(self, keynbr, message, hmac=b''):
        if (type(message)==str):
            message = message.encode('utf8')

        # for message less than one chunk in size
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_SHORT_MESSAGE
        p1= keynbr # oxff=>BIP32 otherwise STD
        p2= 0x00
        le= message.length+2+len(hmac)
        apdu= [cla, ins, p1, p2, le]
        apdu+= [(message.length>>8 & 0xFF), (message.length & 0xFF)]
        apdu+= message+ hmac
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)

    def card_parse_transaction(self, transaction, is_segwit=False):

        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_PARSE_TRANSACTION
        p1= JCconstants.OP_INIT
        p2= 0X01 if is_segwit else 0x00

        # init transaction data and context
        txparser= TxParser(transaction)
        while not txparser.is_parsed():

            chunk= txparser.parse_segwit_transaction() if is_segwit else txparser.parse_transaction()
            lc= len(chunk)
            apdu=[cla, ins, p1, p2, lc]
            apdu+=chunk

            # log state & send apdu
            #if (txparser.is_parsed():
                #le= 86 # [hash(32) | sigsize(2) | sig | nb_input(4) | nb_output(4) | coord_actif_input(4) | amount(8)]
                #logCommandAPDU("cardParseTransaction - FINISH",cla, ins, p1, p2, data, le)
            #elif p1== JCconstants.OP_INIT:
                #logCommandAPDU("cardParseTransaction-INIT",cla, ins, p1, p2, data, le)
            #elif p1== JCconstants.OP_PROCESS:
                #logCommandAPDU("cardParseTransaction - PROCESS",cla, ins, p1, p2, data, le)

            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)

            # switch to process mode after initial call to parse
            p1= JCconstants.OP_PROCESS

        return (response, sw1, sw2)

    def card_sign_transaction(self, keynbr, txhash, chalresponse):
        #if (type(chalresponse)==str):
        #    chalresponse = list(bytes.fromhex(chalresponse))
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_TRANSACTION
        p1= keynbr
        p2= 0x00

        if len(txhash)!=32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")
        elif chalresponse==None:
            data= txhash
        else:
            if len(chalresponse)!=20:
                raise ValueError("Wrong Challenge response length:"+ str(len(chalresponse)) + "(should be 20)")
            data= txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)
    
    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse):
        #if (type(chalresponse)==str):
        #    chalresponse = list(bytes.fromhex(chalresponse))
        cla= JCconstants.CardEdge_CLA
        ins= 0x7A
        p1= keynbr
        p2= 0x00

        if len(txhash)!=32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")
        elif chalresponse==None:
            data= txhash
        else:
            if len(chalresponse)!=20:
                raise ValueError("Wrong Challenge response length:"+ str(len(chalresponse)) + "(should be 20)")
            data= txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag
        lc= len(data)
        apdu=[cla, ins, p1, p2, lc]+data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)
        
    def card_set_2FA_key(self, hmacsha160_key, amount_limit):
        cla= JCconstants.CardEdge_CLA
        ins= 0x79
        p1= 0x00
        p2= 0x00
        le= 28 # data=[ hmacsha160_key(20) | amount_limit(8) ]
        apdu=[cla, ins, p1, p2, le]

        apdu+= hmacsha160_key
        for i in reversed(range(8)):
            apdu+=[(amount_limit>>(8*i))&0xff]

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            self.needs_2FA= True
        return (response, sw1, sw2)

    def card_reset_2FA_key(self, chalresponse):
        cla= JCconstants.CardEdge_CLA
        ins= 0x78
        p1= 0x00
        p2= 0x00
        le= 20 # data=[ hmacsha160_key(20) ]
        apdu=[cla, ins, p1, p2, le]
        apdu+= chalresponse

        # send apdu 
        (response, sw1, sw2) = self.card_transmit(apdu)
        if (sw1==0x90) and (sw2==0x00):
            self.needs_2FA= False
        return (response, sw1, sw2)

    def card_crypt_transaction_2FA(self, msg, is_encrypt=True):
        if (type(msg)==str):
            msg = msg.encode('utf8')
        msg=list(msg)
        msg_out=[]

        # CIPHER_INIT - no data processed
        cla= JCconstants.CardEdge_CLA
        ins= 0x76
        p2= JCconstants.OP_INIT
        blocksize=16
        if is_encrypt:
            p1= 0x02
            lc= 0x00
            apdu=[cla, ins, p1, p2, lc]
            # for encryption, the data is padded with PKCS#7
            size=len(msg)
            padsize= blocksize - (size%blocksize)
            msg= msg+ [padsize]*padsize
            # send apdu
            (response, sw1, sw2) = self.card_transmit(apdu)
            # extract IV & id_2FA
            IV= response[0:16]
            id_2FA= response[16:36]
            msg_out=IV
            # id_2FA is 20 bytes, should be 32 => use sha256
            from hashlib import sha256
            id_2FA= sha256(bytes(id_2FA)).hexdigest()
        else:
            p1= 0x01
            lc= 0x10
            apdu=[cla, ins, p1, p2, lc]
            # for decryption, the IV must be provided as part of the msg
            IV= msg[0:16]
            msg=msg[16:]
            apdu= apdu+IV
            if len(msg)%blocksize!=0:
                print('Padding error!')
            # send apdu
            (response, sw1, sw2) = self.card_transmit(apdu)

        chunk= 192 # max APDU data=256 => chunk<=255-(4+2)
        buffer_offset=0
        buffer_left=len(msg)
        # CIPHER PROCESS/UPDATE (optionnal)
        while buffer_left>chunk:
            p2= JCconstants.OP_PROCESS
            le= 2+chunk
            apdu=[cla, ins, p1, p2, le]
            apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
            apdu+= msg[buffer_offset:(buffer_offset+chunk)]
            buffer_offset+=chunk
            buffer_left-=chunk
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)
            # extract msg
            out_size= (response[0]<<8) + response[1]
            msg_out+= response[2:2+out_size]

        # CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left #following while condition, buffer_left<=chunk
        p2= JCconstants.OP_FINALIZE
        le= 2+chunk
        apdu=[cla, ins, p1, p2, le]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= msg[buffer_offset:(buffer_offset+chunk)]
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        # extract msg
        out_size= (response[0]<<8) + response[1]
        msg_out+= response[2:2+out_size]

        if is_encrypt:
            #convert from list to string
            msg_out= base64.b64encode(bytes(msg_out)).decode('ascii')
            return (id_2FA, msg_out)
        else:
            #remove padding
            pad= msg_out[-1]
            msg_out=msg_out[0:-pad]
            msg_out= bytes(msg_out).decode('latin-1')#''.join(chr(i) for i in msg_out) #bytes(msg_out).decode('latin-1')
            return (msg_out)

    def card_create_PIN(self, pin_nbr, pin_tries, pin, ublk):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CREATE_PIN
        p1= pin_nbr
        p2= pin_tries
        lc= 1 + len(pin) + 1 + len(ublk)
        apdu=[cla, ins, p1, p2, lc] + [len(pin)] + pin + [len(ublk)] + ublk

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)

    #deprecated but used for testcase
    def card_verify_PIN_deprecated(self, pin_nbr, pin):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_VERIFY_PIN
        p1= pin_nbr
        p2= 0x00
        lc= len(pin)
        apdu=[cla, ins, p1, p2, lc] + pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)

    def card_verify_PIN(self):
        if not self.card_present:
            self.client.request('show_error', 'No Satochip found! Please insert card!')
            return
        while (True):
            (response, sw1, sw2, d)=self.card_get_status() # get number of pin tries remaining
            if self.pin is None:
                if d.get("PIN0_remaining_tries",-1)==1:
                    msg = "WARNING: ONLY ONE ATTEMPT REMAINING! Enter the PIN for your Satochip: "
                else:
                    msg = 'Enter the PIN for your Satochip: '
                (is_PIN, pin_0)= self.client.PIN_dialog(msg)
                if not is_PIN:
                    raise RuntimeError(('Device cannot be unlocked without PIN code!'))
                pin_0=list(pin_0)
            else:
                pin_0= self.pin
            cla= JCconstants.CardEdge_CLA
            ins= JCconstants.INS_VERIFY_PIN
            apdu=[cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
            response, sw1, sw2 = self.cardservice.connection.transmit(apdu)
            if sw1==0x90 and sw2==0x00:
                self.set_pin(0, pin_0) #cache PIN value
                return (response, sw1, sw2)
            elif sw1==0x9c and sw2==0x02:
                self.set_pin(0, None) #reset cached PIN value
                pin_left= d.get("PIN0_remaining_tries",-1)-1
                msg = ("Wrong PIN! {} tries remaining!").format(pin_left)
                #self.client.handler.show_error(msg)
                self.client.request('show_error', msg)
            elif sw1==0x9c and sw2==0x0c:
                msg = ("Too many failed attempts! Your Satochip has been blocked! You need your PUK code to unblock it.")
                #self.client.handler.show_error(msg)
                self.client.request('show_error', msg)
                raise RuntimeError('Device blocked with error code:'+hex(sw1)+' '+hex(sw2))

    def set_pin(self, pin_nbr, pin):
        self.pin_nbr=pin_nbr
        self.pin=pin
        return

    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_CHANGE_PIN
        p1= pin_nbr
        p2= 0x00
        lc= 1 + len(old_pin) + 1 + len(new_pin)
        apdu=[cla, ins, p1, p2, lc] + [len(old_pin)] + old_pin + [len(new_pin)] + new_pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        self.set_pin(0, None)
        return (response, sw1, sw2)

    def card_unblock_PIN(self, pin_nbr, ublk):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_UNBLOCK_PIN
        p1= pin_nbr
        p2= 0x00
        lc= len(ublk)
        apdu=[cla, ins, p1, p2, lc] + ublk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        return (response, sw1, sw2)

    def card_logout_all(self):
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_LOGOUT_ALL
        p1= 0x00
        p2= 0x00
        lc=0
        apdu=[cla, ins, p1, p2, lc]
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        self.set_pin(0, None)
        return (response, sw1, sw2)

    def card_init_connect(self):
        print(self.card_get_ATR())
        #response, sw1, sw2 = self.card_select() #TODO: remove?
        
        # check applet version
        while(True):
            (response, sw1, sw2, status)=self.card_get_status()
            if (sw1==0x90 and sw2==0x00):
                v_supported= (CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION
                v_applet= (status["protocol_major_version"]<<8)+status["protocol_minor_version"] 
                print(f"[SatochipPlugin] setup_device(): Satochip version={hex(v_applet)} Electrum supported version= {hex(v_supported)}")#debugSatochip
                if (v_supported<v_applet):
                    msg=(('The version of your Satochip is higher than supported by Electrum. You should update Electrum to ensure correct functioning!')+ '\n' 
                                + f'    Satochip version: {status["protocol_major_version"]}.{status["protocol_minor_version"]}' + '\n' 
                                + f'    Supported version: {CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION}.{CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION}')
                    #self.client.handler.show_message(msg)
                    self.client.request('show_message', msg)
                break
            # setup device (done only once)
            elif (sw1==0x9c and sw2==0x04):
                # PIN dialog
                msg = ("Enter a new PIN for your Satochip:")
                msg_confirm = ("Please confirm the PIN code for your Satochip:")
                msg_error= ("The PIN values do not match! Please type PIN again!")
                (is_PIN, pin_0)= self.client.PIN_setup_dialog(msg, msg_confirm, msg_error)
                if not is_PIN:
                    self.client.request('show_message', "Satochip setup cancelled. \nTo restart setup, click on 'menu' -> 'Setup new Satochip'")
                    return
                pin_0= list(pin_0)
                self.set_pin(0, pin_0) #cache PIN value in client
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
                (response, sw1, sw2)=self.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1!=0x90 or sw2!=0x00:                 
                    print(f"[SatochipPlugin] setup_device(): unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}")#debugSatochip
                    #raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
                    self.client.request('show_error', 'Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
            else:
                print(f"[SatochipPlugin] unknown get-status() error! sw12={hex(sw1)} {hex(sw2)}")#debugSatochip
                #raise RuntimeError('Unknown get-status() error code:'+hex(sw1)+' '+hex(sw2))
                self.client.request('show_error', 'Unknown get-status() error code:'+hex(sw1)+' '+hex(sw2) )
            
        # verify pin:
        try:
            self.card_verify_PIN()
        except Exception as exc:
            self.client.request('show_error', repr(exc))
            return
        
        # get authentikey
        try:
            authentikey=self.card_bip32_get_authentikey()
        except UninitializedSeedError:
            # Option: setup 2-Factor-Authentication (2FA)
            self.init_2FA()
                    
            # seed dialog...
            print("[CardConnector] setup_device(): import seed...") #debugSatochip
            (mnemonic, passphrase, seed)= self.client.seed_wizard()                    
            if seed:
                seed= list(seed)
                authentikey= self.card_bip32_import_seed(seed)
                if authentikey:
                    self.client.request('show_success','Seed successfully imported to Satochip!')
                else:
                    self.client.request('show_error','Error when importing seed to Satochip!')
            else: #if cancel
                self.client.request('show_message','Seed import cancelled!')
                
        hex_authentikey= authentikey.get_public_key_hex(compressed=True)
        print(f"[CardConnector] setup_device(): authentikey={hex_authentikey}")#debugSatochip       
        
    def init_2FA(self):
        if not self.needs_2FA:
            use_2FA=self.client.request('yes_no_question', MSG_USE_2FA)
            if (use_2FA):
                secret_2FA= urandom(20)
                secret_2FA_hex=secret_2FA.hex()
                amount_limit= 0 # i.e. always use 
                try:
                    # the secret must be shared with the second factor app (eg on a smartphone)
                    msg= 'Scan this QR code on your second device \nand securely save a backup of his 2FA-secret: \n'+secret_2FA_hex
                    (event, values)= self.client.request('QRDialog', secret_2FA_hex, None, "Satochip-Bridge: QR Code", True, msg)
                    if event=='Ok':
                        # further communications will require an id and an encryption key (for privacy). 
                        # Both are derived from the secret_2FA using a one-way function inside the Satochip
                        (response, sw1, sw2)=self.card_set_2FA_key(secret_2FA, amount_limit)
                        if sw1!=0x90 or sw2!=0x00:                 
                            print("[CardConnector] Unable to set 2FA!  sw12="+hex(sw1)+" "+hex(sw2))#debugSatochip
                            self.client.request('show_error', 'Unable to setup 2FA with error code:'+hex(sw1)+' '+hex(sw2))
                            #raise RuntimeError('Unable to setup 2FA with error code:'+hex(sw1)+' '+hex(sw2))
                        else:
                            self.needs_2FA=True
                            self.client.request('show_success', '2FA enabled successfully!')
                    else: # Cancel
                        self.client.request('show_message', '2FA activation canceled!')
                except Exception as e:
                    print("[CardConnector] Exception during 2FA activation: "+str(e))    
                    self.client.request('show_error', 'Exception during 2FA activation: '+str(e))
        else:
            self.client.request('show_message', '2FA is already activated!')
    
class AuthenticationError(Exception):
    """Raised when the command requires authentication first"""
    pass

class UninitializedSeedError(Exception):
    """Raised when the device is not yet seeded"""
    pass

class UnexpectedSW12Error(Exception):
    """Raised when the device returns an unexpected error code"""
    pass

if __name__ == "__main__":

    cardconnector= CardConnector()
    cardconnector.card_get_ATR()
    cardconnector.card_select()
    #cardconnector.card_setup()
    cardconnector.card_bip32_get_authentikey()
    #cardconnector.card_bip32_get_extendedkey()
    cardconnector.card_disconnect()
