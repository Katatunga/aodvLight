import queue
import struct
import sys
import time

from HelperClasses import Tbyte

# one = Tbyte(struct.pack('b', 127))
# two = Tbyte(b'\x7f')
# print(one.increase() > two)
#
# header_arr = [1, 0, 129, 254, int('0004'), 23, int('0063'), 65]
# header = b'A' == 65
# print(b'\x41' == b'A')

# op = [b'\xff', 100, b'\xfe', 8, b'\xfd', 2, b'\xfc', 1, b'\xfb', 0, b'\xfa', 1]
#
# for x in [(Tbyte(op[i]), Tbyte(op[i + 1])) for i in range(2, len(op))[0::2]]:
#     print(x[0].address_string(), x[1].byte_string())
# od = set()
# od.update(op)
# print(od)
# od.update([10])
# print(od)
#
# msg_str = b''
# for x in op[::2]:
#     msg_str += Tbyte(x).increase().byte_string()
#
# x = ":".join("{:02x}".format(ord(c)) for c in op[::2])
# print(msg_str.hex(':'))
# print([b'%c' % i for i in msg_str])
# zero = Tbyte(0)
# one = Tbyte(1)
#
# AT_OK = b'AT,OK'
# AT_OK = (AT_OK,) if not hasattr(AT_OK, '__iter__') else AT_OK

# # prof that <> works for Tbytes
# for i in range(0, 256):
#     if one.increase() > zero.increase() and not one.signed() > zero.signed():
#         print(one.signed(), zero.signed())
# print(bytes('hallo'.encode('ascii')))
from Protocol import RouteTableEntry

obj = {}
obj['hallo'] = RouteTableEntry(
    destination_addr='0001',
    dest_sequence_num=Tbyte(0),
    is_route_valid=True,
    is_dest_seq_valid=True,
    hops=Tbyte(10),
    next_hop='0005',
    precursors=set(),
    lifetime=1
)

bla = [str(x) for x in obj.values()]
print(bla)

