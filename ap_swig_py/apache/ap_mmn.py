import apache

if apache.version == (2, 2):
    from apache22.ap_mmn import *
elif apache.version == (2, 0):
    from apache20.ap_mmn import *
elif apache.version == (1, 3):
    from apache13.ap_mmn import *
else:
    raise RuntimeError('Apache version not supported.')
