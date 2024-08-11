import telebot
import requests
import base64
import time
import hmac
import hashlib
import binascii
import json
from Crypto.Cipher import AES

AES_KEY = 'e62efa9ff5ebbc08701f636fcb5842d8760e28cc51e991f7ca45c574ec0ab15c'
TOKEN = 'hjiZQ512eb3247fcf22952f1d9b2af80cf0459450e54eb422dd20798c04'
key = '2Wq7)qkX~cp7)H|n_tc&o+:G_USN3/-uIi~>M+c ;Oq]E{t9)RC_5|lhAA_Qq%_4'
bot_token = '7267359433:AAG_Ej2-srbAXDpSPiOEx85r2_D9QMHoQ1E'
user_id = 1653222949

bot = telebot.TeleBot(bot_token)

class AESCipher(object):
    def __init__(self, AES_KEY):
        self.bs = AES.block_size
        self.AES_KEY = binascii.unhexlify(AES_KEY)

    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = AES.new(self.AES_KEY, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.AES_KEY, AES.MODE_ECB)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

aes = AESCipher(AES_KEY)

def sendPost(url, data, sig, ts):
    headers = {
        'X-App-Version': '4.9.1',
        'X-Token': TOKEN,
        'X-Os': 'android 5.0',
        'X-Client-Device-Id': '14130e29cebe9c39',
        'Content-Type': 'application/json; charset=utf-8',
        'Accept-Encoding': 'deflate',
        'X-Req-Timestamp': ts,
        'X-Req-Signature': sig,
        'X-Encrypted': '1'
    }
    r = requests.post(url, data=data, headers=headers, verify=True)
    return json.loads(aes.decrypt(r.json()['data']))

def getByPhone(phone):
    ts = str(int(time.time()))
    req = f'"countryCode":"RU","source":"search","token":"{TOKEN}","phoneNumber":"{phone}"'
    req = '{'+req+'}'
    string = str(ts)+'-'+req
    sig = base64.b64encode(hmac.new(key, string.encode(), hashlib.sha256).digest()).decode()
    crypt_data = aes.encrypt(req)
    return sendPost('https://pbssrv-centralevents.com/v2.5/search',
                    b'{"data":"'+crypt_data+b'"}', sig, ts)

def getByPhoneTags(phone):
    ts = str(int(time.time()))
    req = f'"countryCode":"RU","source":"details","token":"{TOKEN}","phoneNumber":"{phone}"'
    req = '{'+req+'}'
    string = str(ts)+'-'+req
    sig = base64.b64encode(hmac.new(key, string.encode(), hashlib.sha256).digest()).decode()
    crypt_data = aes.encrypt(req)
    return sendPost('https://pbssrv-centralevents.com/v2.5/number-detail',
                    b'{"data":"'+crypt_data+b'"}', sig, ts)

@bot.message_handler(func=lambda message: message.chat.id == user_id)
def handle_message(message):
    phone = message.text
    if '+' not in phone:
        phone = '+' + phone
    finfo = getByPhone(phone)
    if 'result' in finfo and 'profile' in finfo['result']:
        response = f"Номер: {phone}\n"
        if finfo['result']['profile']['displayName']:
            response += f"Имя: {finfo['result']['profile']['displayName']}\n"
            response += f"Тегов найдено: {finfo['result']['profile']['tagCount']}\n"
            try:
                tags = getByPhoneTags(phone)['result']['tags']
                response += '\n'.join([i['tag'] for i in tags])
            except KeyError:
                if finfo['result']['profile']['tagCount'] > 0:
                    response += "Теги найдены, но для просмотра нужен премиум"
                else:
                    response += "Тегов не найдено!"
        else:
            response += "Не найдено!"
        response += f"\nОсталось обычных поисков: {finfo['result']['subscriptionInfo']['usage']['search']['remainingCount']}/{finfo['result']['subscriptionInfo']['usage']['search']['limit']}"
        response += f"\nС тегами: {finfo['result']['subscriptionInfo']['usage']['numberDetail']['remainingCount']}/{finfo['result']['subscriptionInfo']['usage']['numberDetail']['limit']}"
    else:
        response = "Ошибка при получении данных!"

    bot.send_message(user_id, response)

bot.polling()
