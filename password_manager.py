#Written by Sayali Upasani
#Assignment 1 for Application Security
#the master password to retrieve your password is set to 12345

import sys 
import os
import pickle
import getpass
import pyaes
import pyscrypt

class Passman(object):
    keys = {}
    def __init__(self):
        self.BLOCK_SIZE = 16

    def read(self, filename):
        # to convert the byte stream into dictionary object
        with open(filename, 'rb') as handler:
            self.reader = pickle.load(handler)
        return self.reader

    def write(self, filename, data):
        #to serialize the dictionary into byte stream for storage
        with open(filename, 'wb') as handler:
            self.writer = pickle.dump(data, handler)
        return self.writer

    def _pad(self, password):
        self.x = password
        # Padding the message to be used in ECB and CBC                        
        return self.x + (self.BLOCK_SIZE - len(self.x)%self.BLOCK_SIZE)*chr(self.BLOCK_SIZE - len(self.x)%self.BLOCK_SIZE)

    # encrypt function providing all 3 modes
    def encrypt(self, password, mode, key, iv):
        self.password = password
        if (mode == '1'):
            counter = pyaes.Counter(initial_value = 100)
            aes = pyaes.AESModeOfOperationCTR(key, counter = counter)
            passwordc = aes.encrypt(self.password)
            return passwordc
        
        elif (mode == '2'):
            aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
            passpad = self._pad(password)
            passwordc = aes.encrypt(passpad)
            return passwordc

        elif (mode == '3'):
            aes = pyaes.AESModeOfOperationECB(key)
            passpad = self._pad(password)
            passwordc = aes.encrypt(passpad)
            return passwordc

        else:
            print 'Please select the proper mode of encryption!'
            
    # decrypt function to retrieve the password
    def decrypt(self, passwordc, mode, key,iv):
        self.passwordc = passwordc
        if (mode == '1'):
            counter = pyaes.Counter(initial_value = 100)
            aes = pyaes.AESModeOfOperationCTR(key, counter = counter)
            passwordd = aes.decrypt(passwordc)
            return passwordd
        
        elif (mode == '2'):
            aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
            passwordd = aes.decrypt(passwordc)
            return passwordd
            
        elif (mode == '3'):
            aes = pyaes.AESModeOfOperationECB(key)
            passwordd = aes.decrypt(passwordc)
            return passwordd

master_password = 'AmazingPasswordApp' # ... Static master key to hash

if __name__ == '__main__':
    passman = {}
    keyman = {}
    filename = 'passm.pkl'
    keyfile = 'keym.pkl'
    p = Passman()
    if not os.path.exists(filename):
            open(filename, 'w+').close()

    if not os.path.exists(keyfile):
            open(keyfile, 'w+').close()
    #print passman
    option = raw_input ('Select 1 for registration or 2 for Log In: ')
    if (option == '1'):
        username = raw_input('Please enter your Username: ')
        if os.stat(filename).st_size != 0:
            passman = p.read(filename)
        if username in passman.keys():
            print 'This Username is already taken! '
        else:
            password = getpass.getpass('Please enter your Password: ')
            mode = raw_input('Modes of Encryption: \n 1. CTR Mode \n 2. CBC Mode \n 3. ECB Mode:\n Please select your desired Mode: ')
            ukey = os.urandom(32) #..Generating random key for every username
            key = pyscrypt.hash(master_password, ukey, 1024, 1, 1, 32) #... using hash function to find the key used for encyrption. We use ukey as salt here.
            #key = os.urandom(16).encode('hex')
            #print binascii.hexlify(key)
            iv = os.urandom(16)
            passwordc = p.encrypt(password, mode, key,iv) #.. call encrypt function and pass mode ,key and IV
            #print password
            #print passwordc
            myList =[]
            myList = [ukey, mode, iv] #... to save mode, iv and salt for authenticating user for login process
            if os.stat(filename).st_size != 0:
                passman = p.read(filename) #... reading the contents of pickle file into dictionary
            passman.update({username:passwordc}) #... updating dict with new username and password
            if os.stat(keyfile).st_size != 0:
                keyman = p.read(keyfile) # keyfile contains username and its salt
            keyman.update({username:myList})
            #passman[username] = password
            #print passman
            #print keyman
            p.write(filename, passman) # write updated dict back to pickle file
            p.write(keyfile, keyman)
            print 'You have been registered successfully!'

    elif (option == '2'):
        username = raw_input('Please enter your Username: ')
        #password = raw_input('Please enter your Password: ')
        password = getpass.getpass('Please enter your Password: ')
        if os.stat(filename).st_size != 0:
            passman = p.read(filename)
        if username in passman.keys():
            keyman = p.read(keyfile)
            mode = keyman[username][1]
            ukey = keyman[username][0]
            iv = keyman[username][2]
            key = pyscrypt.hash(master_password, ukey, 1024, 1, 1, 32)
            passwordc = p.encrypt(password, mode, key, iv) #encrypting password again to check for authetication
            if passwordc == passman[username]:
            #if passwordc in passman[username]:
                print 'Authenticated!'
            else: 
                print 'Authentication Error!'
                retrieve = raw_input('Do you wish to retrive your password? Yes  or No: ')
                if (retrieve == 'yes'):
                    masterpass = getpass.getpass('Please Enter the Master Password for this Password Manager: ')
                    if (masterpass == '12345'):
                        passcipher = passman[username]
                        passwordd = p.decrypt(passcipher, mode, key, iv)
                        print 'Your password is:' +passwordd
                    else:
                        print 'Sorry the Master Password you entered is Wrong!'
                else: 
                    print 'Thank you!'
        else:
            print 'Authentication Error!'

    else:
        print 'Enter your Option correctly next time. Bye!'
    
        
