"""
Firefox utilise 3DES pour chiffré les logins en mode CBC, ils sont chiffré est stocké dans le fichier logins.json
celui-ci stocke toutes les connexions de l'utilisateur, y compris les URL, les noms d'utilisateur, les mots de passe au format JSON
les noms d'utilisateur et les mots de passe dans ces fichiers sont chiffrées 3DES,
puis ASN.1 et finalement écrits dans le fichier encodé en base64.
La clé de dechiffrement est stocké dans le fichier key4.db qui correspond a une base de donnée SQLite

Pour réaliser ce script je vais donc devoir réaliser ces etapes : 
1. Extraire la clé principale encodée + chiffrée de key4.db
2. Décodage ASN.1, puis 3DES déchiffre la clé principale
3. lire et désérialiser les connexions chiffrées de logins.json
4. Décodage ASN.1, puis 3DES déchiffre les données de connexion à l'aide de la clé principale
"""
import os
import sys
import sqlite3
import json
import argparse
from base64 import b64decode
from pyasn1.codec.der import decoder
from hashlib import sha1, pbkdf2_hmac
import hmac
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad   
from pathlib import Path

print("******************************************\n******************************************")
print("||\t Anis Harmali's Extractor \t|| pour fonctionner ce script à besoin")
print("||\t Firefox Logins and Cookies \t|| que vous spécifiez le chemin")
print("||\t in Microsoft Windows       \t|| utilisez l'option --help ou -h pour obtenir de l'aide")
print("******************************************\n******************************************\n")

############################### Extration des Logins et MDP ################################## 
parser = argparse.ArgumentParser(description='le nom du dossier contenant key4.db et logins.json utilise un random il faut donc le renseigner pour pouvoir utiliser ce script')
parser.add_argument("--path", help="C:\\Users\\<votre nom d’utilisateur Windows>\\APPDATA\\Mozilla\\Firefox\\Profiles\\<votre random>.default-release", default=os.path.expanduser('~')+"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\w8nsakr8.default-release")
args = parser.parse_args()
local_state_path=args.path

def decryptMoz3DES( globalSalt, entrySalt, encryptedData ):
  hp = sha1( globalSalt ).digest()
  pes = entrySalt + b'\x00'*(20-len(entrySalt))
  chp = sha1( hp+entrySalt ).digest()
  k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
  tk = hmac.new(chp, pes, sha1).digest()
  k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
  k = k1+k2
  iv = k[-8:]
  key = k[:24]
  return DES3.new( key, DES3.MODE_CBC, iv).decrypt(encryptedData)

def decodeLoginData(data):
  asn1data = decoder.decode(b64decode(data)) # decodage base64, puis ASN1
  key_id = asn1data[0][0].asOctets()
  iv = asn1data[0][1][1].asOctets()
  ciphertext = asn1data[0][2].asOctets()
  return key_id, iv, ciphertext 

def getLoginData():
  logins = []
  json_file = local_state_path + "\\logins.json"
  loginf = open( json_file, 'r').read()
  jsonLogins = json.loads(loginf)
  for row in jsonLogins['logins']:
    encUsername = row['encryptedUsername']
    encPassword = row['encryptedPassword']
    logins.append( (decodeLoginData(encUsername), decodeLoginData(encPassword), row['hostname']) )
  return logins

def decryptPBE(decodedItem, globalSalt): #PBE pour Password Based Encryption 
  pbeAlgo = str(decodedItem[0][0][0])
  if pbeAlgo == '1.2.840.113549.1.12.5.1.3': #pbeWithSha1AndTripleDES-CBC
    entrySalt = decodedItem[0][0][1][0].asOctets()
    cipherT = decodedItem[0][1].asOctets()
    key = decryptMoz3DES( globalSalt, entrySalt, cipherT )
    return key[:24]
  elif pbeAlgo == '1.2.840.113549.1.5.13': #pkcs5 pbes2  
    entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
    iterationCount = int(decodedItem[0][0][1][0][1][1])
    keyLength = int(decodedItem[0][0][1][0][1][2])
    k = sha1(globalSalt).digest()
    key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)    
    iv = b'\x04\x0e'+decodedItem[0][0][1][1][1].asOctets()
    cipherT = decodedItem[0][1].asOctets()
    clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)
    return clearText

def getKey( ):  
    conn = sqlite3.connect(local_state_path + "\\key4.db")
    c = conn.cursor()
    c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
    row = c.fetchone()
    globalSalt = row[0] #item1
    item2 = row[1]
    decodedItem2 = decoder.decode( item2 ) 
    clearText = decryptPBE( decodedItem2, globalSalt )
    if clearText == b'password-check\x02\x02': 
      c.execute("SELECT a11,a102 FROM nssPrivate;")
      for row in c:
        if row[0] != None:
            break
      a11 = row[0]
      a102 = row[1] 
      if a102 != None: 
        decoded_a11 = decoder.decode( a11 )
        clearText= decryptPBE( decoded_a11, globalSalt )
        return clearText[:24]
      else:
        print('no login/password')      
    return None

key = getKey()
logins = getLoginData()

print('======================== login and password ========================')
print('')
for i in logins:
    print ('%20s:' % (i[2]),end=' login: ')
    iv = i[0][1]
    ciphertext = i[0][2] 
    print ( unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 ), end=' password: ')
    iv = i[1][1]
    ciphertext = i[1][2] 
    print ( unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 ) )
print('')    
print('====================================================================')
print('')
print("# l'extraction des cookies est redirigé vers le fichier cookies.txt car parfois trop grand # \n")
input('Press ENTER to exit')
############################### Extraction des Cookies #####################################
dbfile = local_state_path
con = sqlite3.connect(local_state_path+"\\cookies.sqlite")
cur = con.cursor()
data = cur.execute('select host,name from moz_cookies')
sys.stdout = open('cookies.txt','w')
for host, name in data.fetchall():
	print(f"""
    Host: {host}
    Cookie name: {name}
    ===============================================================
    """)
sys.stdout.close()




