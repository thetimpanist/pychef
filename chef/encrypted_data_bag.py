from chef.data_bag import DataBag, DataBagItem
from chef.exceptions import ChefError, ChefServerNotFoundError
from chef.utils import json

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 

class EncryptedDataBag(DataBag):

    def __init__(self, name, api=None, skip_load=False):
        super(EncryptedDataBag, self) \
            .__init__(name, api=api, skip_load=skip_load)

    def obj_class(self, name, api):
        return EncryptedDataBagItem(self, name, api=api)


class EncryptedDataBagItem(DataBagItem):
    """ At the moment, this only handles version 1 encryptions and AES-256-CBC
        algorithms.

    """
    _VERSION = 1
    _ALGORITHM = "aes-256-cbc"

    def __init__(self, bag, name, key, api=None, skip_load=False):
        super(EncryptedDataBagItem, self).__init__(
            bag, name, api=api, skip_load=skip_load
        )
        self._key = key

    def _cipher(self, iv, mode=AES.MODE_CBC): 
        key = SHA256.new(self._key).digest()
        return AES.new(key, mode, b64decode(iv))

    def _gen_iv(self):
        return b64encode(Random.new().read(AES.block_size))

    def _pad(self, data):
        pad_length = AES.block_size - len(data) % AES.block_size
        return data + chr(pad_length) * pad_length

    def _populate(self, data):
        super(EncryptedDataBagItem, self)._populate(data)

        raw_data = {}
        for key in self.raw_data:
            if 'encrypted_data' in self.raw_data[key] and \
                self.raw_data[key]['version'] == self._VERSION and \
                self.raw_data[key]['cipher'] == self._ALGORITHM:

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
        # print(data)
        if data.startswith('{"json_wrapper"'):
            return data[data[1:].find('{')+1:data.rfind('}')]
        return data

    def _wrap(self, data):
        return '{"json_wrapper":%s}' % \
            (json.dumps(data).replace(", ", ",").replace(": ", ":"),)

    def encrypt_data(self):
        encrypted_data = {}
        for key in self.raw_data:
            if key != "id": # check not alrady encrypted
                iv = self._gen_iv()
                cipher = self._cipher(iv)
                encrypted_data[key] = {
                    "encrypted_data": b64encode(cipher.encrypt(
                        self._pad(self._wrap(self.raw_data[key]))
                    )).decode(),
                    "iv": iv.decode(),
                    "version": self._VERSION,
                    "cipher": self._ALGORITHM
                }
            else:
                encrypted_data[key] = self.raw_data[key]
        return encrypted_data


    def save(self, api=None):
        api = api or self.api
        self['id'] = self.name

        encrypted_data = self.encrypt_data()
        print(encrypted_data)

        try:
            api.api_request('PUT', self.url, data=encrypted_data)
        except ChefServerNotFoundError as e:
            pass
            # api.api_request('POST', self.__class__.url + '/' +str(self._bag), 
            #     data=encrypted_data
            # )

