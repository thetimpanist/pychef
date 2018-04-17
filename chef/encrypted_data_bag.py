from chef.data_bag import DataBag, DataBagItem
from chef.exceptions import ChefError, ChefServerNotFoundError
from chef.utils import json
from chef.api import ChefAPI

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

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
    _VERSIONS = (1,3,)

    def __init__(self, bag, name, key, api=None, skip_load=False):
        super(EncryptedDataBagItem, self).__init__(
            bag, name, api=api, skip_load=skip_load
        )
        self._key = key

    def _populate(self, data):
        super(EncryptedDataBagItem, self)._populate(data)

        raw_data = {}
        for key in self.raw_data:
            if 'encrypted_data' in self.raw_data[key]:
                cipher = Cipher.factory(self._key, self.raw_data[key])
                decrypted_data = cipher.decrypt()
                raw_data[key] = json.loads(self._strip_wrapper(decrypted_data))
            else:
                raw_data[key] = self.raw_data[key]

        self._encrypted_data = self.raw_data # save an actual raw copy
        self.raw_data = raw_data

    def _strip_wrapper(self, data):
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

                data = self._encrypted_data[key] \
                    if key in self._encrypted_data else {}
                cipher = Cipher.factory(self._key, data)
                encrypted_data[key] = {
                    "encrypted_data": cipher.encrypt(
                        self._wrap(self.raw_data[key])
                    ),
                    "iv": cipher.iv,
                    "version": cipher.version(),
                    "cipher": cipher.algorithm()
                }
                if cipher.include_auth():
                    encrypted_data[key]['auth_tag'] = cipher.auth_tag() 
            else:
                encrypted_data[key] = self.raw_data[key]
        return encrypted_data

    @classmethod
    def create(cls, bag, name, key, api=None, **kwargs):
        """Create a new data bag item. Pass the initial value for any keys as
        keyword arguments."""
        api = api or ChefAPI.get_global()
        obj = cls(bag, name, key, api, skip_load=True)
        for key, value in six.iteritems(kwargs):
            obj[key] = value
        obj.save()
        if isinstance(bag, EncryptedDataBag) and name not in bag.names:
            # Mutate the bag in-place if possible, so it will return the new
            # item instantly
            bag.names.append(name)
        return obj

    def save(self, api=None):
        api = api or self.api
        self['id'] = self.name

        encrypted_data = self.encrypt_data()

        try:
            api.api_request('PUT', self.url, data=encrypted_data)
        except ChefServerNotFoundError as e:
            api.api_request('POST', self.__class__.url + '/' +str(self._bag), 
                data=encrypted_data
            )

class Cipher(object):
    """Cipher object for encrypted data bag items."""

    _ALGORITHMS = {
        "aes-256-cbc": AES.MODE_CBC,
        "aes-256-gcm": AES.MODE_GCM
        }

    def __init__(self, key, field):
        self.assert_correct_version(field)
        self.key = key
        self.iv = self.gen_iv() if 'iv' not in field else field['iv']
        self.field = field
        self.cipher = self._cipher(self.iv)

    def factory(key, field):
        if 'version' not in field or field['version'] == 3:
            return CipherV3(key, field)
        elif field['version'] == 1:
            return CipherV1(key, field)
        else:
            raise ValueError("Unknown encryption version.")

    def _cipher(self, iv, algorithm=None):
        algorithm = algorithm or self.algorithm()
        key = SHA256.new(self.key).digest()
        return AES.new(key, self._ALGORITHMS[algorithm], b64decode(iv))

    def gen_iv(self, size):
        return b64encode(Random.new().read(size)).decode()

    def _pad(self, data):
        raise NotImplementedError("Unknown padding type.")

    def version(self):
        raise NotImplementedError("Invalid Cipher Version.")

    def algorithm(self):
        raise NotImplementedError("Invalid Cipher Algorithm.")

    def assert_correct_version(self, field):
        assert 'version' not in field or field['version'] == self.version()
        assert 'cipher' not in field or field['cipher'] == self.algorithm()

    def decrypt(self):
        raise NotImplementedError("Abstract Cipher Class.")

    def encrypt(self, data):
        if type(data) is not bytes:
            data = data.encode()
        return b64encode(self.cipher.encrypt(self._pad(data))).decode()

    def include_auth(self):
        return False

class CipherV1(Cipher):

    def gen_iv(self, size=AES.block_size):
        return super(CipherV1, self).gen_iv(size)

    def _pad(self, data):
        if type(data) is bytes:
            data = data.decode()
        pad_length = AES.block_size - len(data) % AES.block_size
        return (data + chr(pad_length) * pad_length).encode()

    def algorithm(self):
        return 'aes-256-cbc'

    def version(self):
        return 1

    def decrypt(self):
        return self.cipher.decrypt(
            b64decode(self.field['encrypted_data'])
        ).decode()

class CipherV3(Cipher):

    def gen_iv(self, size=12):
        return super(CipherV3, self).gen_iv(size)

    def _pad(self, data):
        return data # gcm requires no padding

    def algorithm(self):
        return 'aes-256-gcm'

    def version(self):
        return 3

    def include_auth(self):
        return True

    def decrypt(self):
        return self.cipher.decrypt_and_verify(
            b64decode(self.field['encrypted_data']), 
            b64decode(self.field['auth_tag'])
        ).decode()

    def auth_tag(self):
        return b64encode(self.cipher.digest()).decode()

