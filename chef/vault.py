import six
from base64 import b64decode, b64encode

from chef.encrypted_data_bag import EncryptedDataBag, EncryptedDataBagItem
from chef.data_bag import DataBagItem
from chef.exceptions import ChefError, ChefServerNotFoundError
from chef.api import ChefAPI

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

        self._key = self._secret(self._keys.api) if not skip_load else None
        super(VaultItem, self).__init__(bag, name, self._key, api=api, 
            skip_load=skip_load
        )

    def _vault_cipher(self, api=None):
        api = api or self.api
        key = RSA.importKey(api.key.private_export())
        return PKCS1_v1_5.new(key)

    def _secret(self, api):
        if api.client not in self._keys.raw_data:
            raise ChefError("%s/%s is not encrypted with your public key." % \
                (self._bag, self.name)
            )

        cipher = self._vault_cipher(api)
        dsize = SHA.digest_size
        sentinel = Random.new().read(15+dsize)
        return cipher.decrypt(b64decode(self._keys.raw_data[api.client]), 
                sentinel)

    def _gen_secret(self, size=32):
        return Random.new().read(size)

    def _create_keys(self, api=None):
        api = api or self.api
        temp_keys = DataBagItem(self._bag, '%s_keys' % (self.name,), 
            self.api
        )

        if not not temp_keys.raw_data: # make sure we don't overwrite keys that already exist
            raise ChefError("This library does not yet support the overwriting of existing vault keys.")

        cipher = self._vault_cipher()
        secret = self._gen_secret()
        self._keys.raw_data[api.client] = b64encode(cipher.encrypt(secret))\
            .decode()
        self._keys.save()
        self._key = secret # set this after we have a successful save
            
    @classmethod
    def create(cls, bag, name, api=None, **kwargs):
        """Create a new data bag item. Pass the initial value for any keys as
        keyword arguments."""
        api = api or ChefAPI.get_global()
        obj = cls(bag, name, api, skip_load=True)
        for key, value in six.iteritems(kwargs):
            obj[key] = value
        obj.save()
        if isinstance(bag, Vault) and name not in bag.names:
            # Mutate the bag in-place if possible, so it will return the new
            # item instantly
            bag.names.append(name)
        return obj


    def save(self, api=None):
        api = api or self.api
        self['id'] = self.name

        try:
            if not self._key:
                raise ChefServerNotFoundError("Key not loaded.")
            encrypted_data = self.encrypt_data()
            api.api_request('PUT', self.url, data=encrypted_data)
        except ChefServerNotFoundError as e:
            self._create_keys()
            encrypted_data = self.encrypt_data()
            api.api_request('POST', self.__class__.url + '/' +str(self._bag), 
                data=encrypted_data
            )
