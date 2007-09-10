import apache

if apache.version == (2, 2):
    from apache22.ap_mpm import *
elif apache.version == (2, 0):
    from apache20.ap_mpm import *
elif apache.version == (1, 3):
    from apache13.ap_mpm import *
else:
    raise RuntimeError('Apache version not supported.')
