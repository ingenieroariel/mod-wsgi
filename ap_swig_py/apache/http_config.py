import apache

if apache.version == (2, 2):
    from apache22.http_config import *
elif apache.version == (2, 0):
    from apache20.http_config import *
elif apache.version == (1, 3):
    from apache13.http_config import *
else:
    raise RuntimeError('Apache version not supported.')
