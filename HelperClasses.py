from __future__ import annotations

import struct
import threading


class Tbyte:

    def __init__(self, value: int):
        self.lock = threading.RLock()
        if isinstance(value, Tbyte):
            self.num_rep = value.num_rep
        elif isinstance(value, bytes):
            self.num_rep = struct.unpack('B', value)[0]
        elif 0 <= value < 256:
            self.num_rep = value
        else:
            raise TypeError('Value is not a byte-string or byte-valued number')

    # TODO: ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # TODO: GROESSER KLEINER STIMMT SO NICHT
    # TODO: ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    def __eq__(self, other: Tbyte):
        return self.num_rep == other.num_rep

    def __gt__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is greater"""
        return (self.signed() - other.signed()) & 0xff > 0

    def __lt__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is lesser"""
        return (self.signed() - other.signed()) & 0xff < 0

    def __ge__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is greater"""
        return (self.signed() - other.signed()) & 0xff >= 0

    def __le__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is lesser"""
        return (self.signed() - other.signed()) & 0xff <= 0

    def __ne__(self, other: Tbyte):
        return self.num_rep != other.num_rep

    def signed(self) -> int:
        return struct.unpack('b', struct.pack('B', self.num_rep))[0]

    def unsigned(self) -> int:
        return self.num_rep

    def byte_string(self) -> bytes:
        return struct.pack('B', self.num_rep)

    def address_string(self) -> str:
        """Translates the unsigned byte value to a LoRa-Module address (0001 - 0020)"""
        return '0' * (4 - len(str(self.unsigned()))) + str(self.unsigned())

    def increase(self):
        with self.lock:
            self.num_rep = (self.num_rep + 1) & 0xff
            return self

    def decrease(self):
        with self.lock:
            self.num_rep = (self.num_rep - 1) if self.num_rep > 0 else 255
            return self

    def copy(self):
        return Tbyte(self)


class RREQ:
    def __init__(self, hop_count: Tbyte, rreq_id: Tbyte, origin_addr: Tbyte,
                 origin_seq_num: Tbyte, dest_addr: Tbyte, dest_seq_num: Tbyte):
        self.msg_type = Tbyte(1)
        self.u_flag = Tbyte(0)
        if dest_seq_num is None:
            u_flag = Tbyte(1)
            dest_seq_num = Tbyte(0)
        self.hop_count = hop_count
        self.rreq_id = rreq_id
        self.origin_addr = origin_addr
        self.origin_seq_num = origin_seq_num
        self.dest_addr = dest_addr
        self.dest_seq_num = dest_seq_num
        
    def increase_rreq_id(self):
        self.rreq_id.increase()
        return self
    
    def to_bytestring(self):
        bs = b''
        attributes = [self.msg_type, self.u_flag, self.hop_count, self.rreq_id, self.origin_addr,
                 self.origin_seq_num, self.dest_addr, self.dest_seq_num]
        for attr in attributes:
            bs += attr.byte_string()

        return bs


class SendTextRequest:
    def __init__(self, origin_addr: Tbyte, dest_addr: Tbyte, msg_id: Tbyte, payload: bytes):
        self.msg_type = 5
        self.origin_addr = origin_addr
        self.dest_addr = dest_addr
        self.msg_id = msg_id
        self.payload = payload

    def to_bytestring(self):
        bs = b''
        attributes = [self.msg_type, self.origin_addr, self.dest_addr, self.msg_id, self.payload]
        for attr in attributes:
            bs += attr.byte_string()

        return bs
