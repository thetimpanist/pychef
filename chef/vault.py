from base64 import b64decode

from chef.encrypted_data_bag import EncryptedDataBag, EncryptedDataBagItem
from chef.data_bag import DataBagItem
from chef.exceptions import ChefError

from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Hash import SHA, SHA256
from Crypto import Random

class Vault(EncryptedDataBag):

    def __init__(self, name, api=None, skip_load=False):
        super(Vault, self).__init__(name, api=api, skip_load=skip_load)

    def obj_class(self, name, api):
        return VaultItem(self, name, api=api)

    def _populate(self, data):
        self.names = [key for key in data.keys() if key[-5:] != '_keys']

class VaultItem(EncryptedDataBagItem):
    
    def __init__(self, bag, name, api=None, skip_load=False):
        self._keys = DataBagItem(bag, '%s_keys' % (name,), api=api, 
            skip_load=skip_load
        )

        self._key = self._secret(self._keys.api)
        super(VaultItem, self).__init__(bag, name, self._secret(self._keys.api), 
            api=api, skip_load=skip_load
        )

    def _secret(self, api):
        if api.client not in self._keys.raw_data:
            raise ChefError("%s/%s is not encrypted with your public key." % \
                (self._bag, self.name)
            )

        key = RSA.importKey(api.key.private_export())
        cipher = PKCS1_v1_5.new(key)
        dsize = SHA.digest_size
        sentinel = Random.new().read(15+dsize)
        return cipher.decrypt(b64decode(self._keys.raw_data[api.client]), 
                sentinel)
