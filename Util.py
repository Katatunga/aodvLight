from __future__ import annotations

import struct
import threading
import time
from typing import Optional, Union


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

    def __eq__(self, other: Tbyte):
        return self.num_rep == other.num_rep

    def __gt__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is greater"""
        return Tbyte((self.signed() - other.signed()) & 0xff).signed() > 0

    def __lt__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is lesser"""
        return Tbyte((self.signed() - other.signed()) & 0xff).signed() < 0

    def __ge__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is greater"""
        return self > other or self == other

    def __le__(self, other: Tbyte):
        """Uses signed representation of bytes to evaluate which is lesser"""
        return self < other or self == other

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
        return Tbyte(self.unsigned())


class RREQ:
    def __init__(self, u_flag: Tbyte, hop_count: Tbyte, rreq_id: Tbyte, origin_addr: Tbyte,
                 origin_seq_num: Tbyte, dest_addr: Tbyte, dest_seq_num: Tbyte):
        self.msg_type = Tbyte(1)

        self.u_flag = u_flag
        self.dest_seq_num = dest_seq_num
        self.hop_count = hop_count
        self.rreq_id = rreq_id
        self.origin_addr = origin_addr
        self.origin_seq_num = origin_seq_num
        self.dest_addr = dest_addr

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
    def __init__(self, origin_addr: Tbyte, dest_addr: Tbyte, msg_id: Tbyte, payload: bytes, display_id: int):
        self.msg_type = Tbyte(5)
        self.origin_addr = origin_addr
        self.dest_addr = dest_addr
        self.msg_id = msg_id
        self.payload = payload
        self.display_id = display_id

    def to_bytestring(self):
        bs = b''
        attributes = [self.msg_type, self.origin_addr, self.dest_addr, self.msg_id]
        for attr in attributes:
            bs += attr.byte_string()

        bs += self.payload

        return bs


class ProtocolError(Exception):
    def __init__(self, message: str):
        self.message = message


class RouteTableEntry:
    def __init__(self,
                 destination_addr: str, dest_sequence_num: Tbyte, is_dest_seq_valid: bool,
                 is_route_valid: bool, hops: Tbyte, next_hop: str, precursors: set[str], lifetime: float):
        self.destination_addr = destination_addr
        self.dest_sequence_num = dest_sequence_num
        self.is_dest_seq_valid = is_dest_seq_valid
        self.is_route_valid = is_route_valid
        self.hops = hops
        self.next_hop = next_hop
        self.precursors = precursors
        self.expiry_time = lifetime

    def __str__(self) -> str:
        return \
            f'dest_addr: {self.destination_addr}' \
            f'; dest_seq_num: {self.dest_sequence_num.unsigned()}' \
            f'; is_dest_seq_valid: {self.is_dest_seq_valid}' + \
            f'; is_route_valid: {self.is_route_valid}' \
            f'; hops: {self.hops.unsigned()}' \
            f'; next_hop: {self.next_hop}' \
            f'; precursors: {self.precursors}' \
            f'; expiry_time: {self.expiry_time}'

    def is_valid_and_alive(self):
        """
        Checks if this route is valid and not expired.
        :return: True if the route is valid and it's lifetime is not expired, False otherwise.\n
        """
        return self.is_route_valid and self.expiry_time > time.time()

    def to_delete(self):
        """
        Returns True if this route is invalid and its delete period is expired.\n
        :return: True if the route is invalid and it's lifetime (delete period) is expired, False otherwise
        """
        return self.is_route_valid is False and self.expiry_time < time.time()

    def invalidate(self, delete_period: Union[float, int]):
        """Invalidates this route and sets its expiry_time to time.time() + DELETE_PERIOD"""
        self.is_route_valid = False
        self.expiry_time = time.time() + delete_period


class TimedTask:
    def __init__(self, time_to_call: float, task_type: str, callback: callable, args: list):
        self.time_to_call = time_to_call
        self.task_type = task_type
        self.callback = callback
        self.args = args

    def is_due(self) -> bool:
        return self.time_to_call < time.time()
