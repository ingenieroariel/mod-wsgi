import apache

if apache.version == (2, 2):
    from apache22.apr_strings import *
elif apache.version == (2, 0):
    from apache20.apr_strings import *
elif apache.version == (1, 3):
    from apache13.apr_strings import *
else:
    raise RuntimeError('Apache version not supported.')
