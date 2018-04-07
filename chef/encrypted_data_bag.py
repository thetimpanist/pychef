from chef.data_bag import DataBag, DataBagItem
from chef.exceptions import ChefError
from chef.utils import json

from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

class EncryptedDataBag(DataBag):

    def __init__(self, name, api=None, skip_load=False):
        super(EncryptedDataBag, self) \
            .__init__(name, api=api, skip_load=skip_load)

    def obj_class(self, name, api):
        return EncryptedDataBagItem(self, name, api=api)


class EncryptedDataBagItem(DataBagItem):

    def __init__(self, bag, name, key, api=None, skip_load=False):
        super(EncryptedDataBagItem, self).__init__(
            bag, name, api=api, skip_load=skip_load
        )
        self._key = key

    def _cipher(self, iv, mode=AES.MODE_CBC): 
        key = SHA256.new(self._key).digest()
        return AES.new(key, mode, b64decode(iv))

    def _populate(self, data):
        super(EncryptedDataBagItem, self)._populate(data)

        raw_data = {}
        for key in self.raw_data:
            if 'encrypted_data' in self.raw_data[key]:
                cipher = self._cipher(self.raw_data[key]['iv'])
                raw_data[key] =  json.loads(self._strip_wrapper(
                    cipher.decrypt(b64decode(
                        self.raw_data[key]['encrypted_data'])
                    ).decode()
                ))
            else:
                raw_data[key] = self.raw_data[key]
        self.raw_data = raw_data

    def _strip_wrapper(self, data):
        if data.startswith('{"json_wrapper"'):
            return data[data[1:].find('{')+1:data.rfind('}')]
        return data
        

