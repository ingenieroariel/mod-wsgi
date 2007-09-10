import apache

if apache.version == (2, 2):
    from apache22.http_request import *
elif apache.version == (2, 0):
    from apache20.http_request import *
elif apache.version == (1, 3):
    from apache13.http_request import *
else:
    raise RuntimeError('Apache version not supported.')
