import queue
import struct
import sys
import time

from Util import Tbyte

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
# currently = Tbyte(0)
# one = Tbyte(1)
#
# AT_OK = b'AT,OK'
# AT_OK = (AT_OK,) if not hasattr(AT_OK, '__iter__') else AT_OK

# prof that <> works for Tbytes

# currently = Tbyte(1)
# incoming = Tbyte(0)
#
# for i in range(0, 512):
#     incoming.increase()
#     currently.increase()
#     if currently > incoming:
#         print('incoming stale')

# print(bytes('hallo'.encode('ascii')))

# from Protocol import RouteTableEntry
#
# obj = {}
# obj['hallo'] = RouteTableEntry(
#     destination_addr='0001',
#     dest_sequence_num=Tbyte(0),
#     is_route_valid=True,
#     is_dest_seq_valid=True,
#     hops=Tbyte(10),
#     next_hop='0005',
#     precursors=set(),
#     lifetime=1
# )
#
# bla = [str(x) for x in obj.values()]
# print(bla)

# state = 'Pending'
# first_line_str = '\n' + ('-' * 10) + state + ('-' * (10 - 1))
# msg = '\n----------------Hallpo----------------\nOla\n----------------------------------------\n'
# end_of_first_line = msg.index('\n', 1)
# msg = first_line_str + msg[end_of_first_line:]
# print(msg)

LINEBREAK = b'\r\n'

msg = b'LR,0004,0c,1234\r\n'  # 567890\r\n
# remove LINEBREAK
msg = msg.rstrip(LINEBREAK)
print(msg)

# handle actual messages from outside TODO: on incomplete messages somehow everything after is incomplete
if msg.startswith(b'LR'):
    # if message incomplete, read rest
    msg_arr = msg.split(b',', 3)
    print(msg_arr, msg)
    # TODO Incoming message is incomplete, discarded - Ignored message: b',0009,08,\x01\x01\x00\x01\t\x01\x06\x00
    expected_length = int(msg_arr[2].decode('ascii'), base=16)
    print(expected_length, len(msg_arr[3]))
    if len(msg_arr[3]) < expected_length:
        # reattach LINEBREAK which apparently was part of message
        msg += LINEBREAK
        print(msg)
        # read remaining bytes of content
        print('read ' + str(expected_length - 2 - len(msg_arr[3])))
        # remove following LINEBREAK from input
        #ser.read(2)
