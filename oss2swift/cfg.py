from swift.common.utils import config_true_value


class Config(dict):
    def __init__(self, base=None):
        if base is not None:
            self.update(base)

    def __getattr__(self, name):
        if name not in self:
            raise AttributeError("No attribute '%s'" % name)

        return self[name]

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        del self[name]

    def update(self, other):
        if hasattr(other, 'keys'):
            for key in other.keys():
                self[key] = other[key]
        else:
            for key, value in other:
                self[key] = value

    def __setitem__(self, key, value):
        if isinstance(self.get(key), bool):
            dict.__setitem__(self, key, config_true_value(value))
        elif isinstance(self.get(key), int):
            dict.__setitem__(self, key, int(value))
        else:
            dict.__setitem__(self, key, value)

# Global config dictionary.  The default values can be defined here.


CONF = Config({
    'allow_no_owner': True,
    'location': ['Hangzhou', 'Shanghai', 'Shenzhen'],
    'dns_compliant_bucket_names': True,
    'max_corerule_listing':10,
    'max_bucket_listing': 1000,
    'max_parts_listing': 1000,
    'max_multi_delete_objects': 1000,
    'oss_acl': True,
    'storage_domain': 'oss-ostorage.com',
    'auth_pipeline_check': True,
    'max_upload_part_num': 1000,
    'check_bucket_owner': True,
    'force_swift_request_proxy_log': True,
    'allow_multipart_uploads': True,
})
