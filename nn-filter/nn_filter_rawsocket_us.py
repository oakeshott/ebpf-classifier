import sys
import os
import ctypes as ct
from ctypes import CDLL, POINTER
from ctypes import c_size_t, c_int32
import joblib
import numpy as np
import json

curdir = os.path.dirname(__file__)
def ensure_contiguous(array):
    return np.ascontiguousarray(array) if not array.flags['C_CONTIGUOUS'] else array

if __name__ == '__main__':
    lib = CDLL(f"{curdir}/nn_filter.so")

    resdir = sys.argv[2]
    nn_filter = lib.nn_filter
    seconds = 10
    c_uint_p = ct.POINTER(ct.c_uint)
    ret = ensure_contiguous(np.zeros(seconds, dtype=np.uintc))
    _ret = ret.ctypes.data_as(c_uint_p)
    nn_filter.argstypes = [c_int32]
    nn_filter.restype = None

    nn_filter(seconds, _ret)
    # print(np.ctypeslib.as_array(_ret, seconds))
    filename = f"{resdir}/rxpps.log"
    with open (filename, "w") as f:
        for d in np.ctypeslib.as_array(ret, seconds):
            f.write(f"{d}\n")
        # json.dump(, f)

