import apache

if apache.version == (2, 2):
    from apache22.mod_auth import *
else:
    raise RuntimeError('Apache version not supported.')
