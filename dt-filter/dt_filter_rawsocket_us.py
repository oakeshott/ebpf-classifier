import sys
import os
import ctypes as ct
from ctypes import CDLL, POINTER
from ctypes import c_size_t, c_int32
import json
import numpy as np

curdir = os.path.dirname(__file__)
def ensure_contiguous(array):
    return np.ascontiguousarray(array) if not array.flags['C_CONTIGUOUS'] else array
if __name__ == '__main__':
    prefix_path = f"{curdir}/runs"
    with open(f'{prefix_path}/childrenLeft', 'r') as f:
        children_left = np.array(json.load(f))
    with open(f'{prefix_path}/childrenRight', 'r') as f:
        children_right = np.array(json.load(f))
    with open(f'{prefix_path}/threshold', 'r') as f:
        threshold = np.array(json.load(f))
    with open(f'{prefix_path}/feature', 'r') as f:
        feature = np.array(json.load(f))
    with open(f'{prefix_path}/value', 'r') as f:
        value = np.array(json.load(f))

    # value = np.array(value)
    # print(value)
    lib = CDLL(f"{curdir}/dt_filter.so")

    dt_filter = lib.dt_filter
    seconds = 110

    # ND_POINTER_1 = np.ctypeslib.ndpointer(dtype=children_left.dtype, ndim=1, flags="C_CONTIGUOUS")
    children_left_pointer  = children_left.ctypes.data_as(POINTER(ct.c_longlong))
    children_right_pointer = children_right.ctypes.data_as(POINTER(ct.c_longlong))
    threshold_pointer      = threshold.ctypes.data_as(POINTER(ct.c_longlong))
    feature_pointer        = feature.ctypes.data_as(POINTER(ct.c_longlong))
    value_pointer          = value.ctypes.data_as(POINTER(ct.c_longlong))
    c_uint_p = ct.POINTER(ct.c_uint)
    ret = ensure_contiguous(np.zeros(seconds, dtype=np.uintc))
    _ret = ret.ctypes.data_as(c_uint_p)

    dt_filter.argstypes = [c_int32, POINTER(ct.c_longlong), POINTER(ct.c_longlong), POINTER(ct.c_longlong), POINTER(ct.c_longlong), POINTER(ct.c_longlong), c_size_t]
    # dt_filter.argstypes = [ND_POINTER_1, c_size_t]
    dt_filter.restype = None

    # print(dt_filter(children_left))
    dt_filter(seconds, children_left_pointer, children_right_pointer, value_pointer, feature_pointer, threshold_pointer, children_left.size, _ret)
    # print(dt_filter(children_left, children_left.size))

    resdir = sys.argv[2]

    filename = f"{resdir}/rxpps.log"
    with open (filename, "w") as f:
        for d in np.ctypeslib.as_array(ret, seconds):
            f.write(f"{d}\n")
