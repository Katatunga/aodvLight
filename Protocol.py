import queue
import struct
import time

from typing import Dict, Optional, Union

from HelperClasses import Tbyte, SendTextRequest, RREQ

# default expiry_time of a route until it becomes invalid (sec)
DEFAULT_LIFETIME = 180
# Time in secs to wait for RREP or S-T-R-ACK
PATH_DISCOVERY_TIME = 30
# Number of repetitions if no answer was received
MSG_REPEATS = 2
# time in seconds to wait for a RREP-ACK before resending RREP / blacklisting or giving up
RREP_ACK_WAIT = 10
# time in seconds an invalid route exists before deletion
DELETE_PERIOD = 180  # TODO should also be waiting time on startup, before forwarding messages -> AODV 6.13
# Number of repetitions for RREQs
RREQ_REPEAT = 2
# Number of repetitions for RREQs
RREP_REPEAT = 2
# Number of repetitions for RREQs
S_T_R_REPEAT = 2
# Timeout in seconds to ignored addresses
BLACKLIST_TIMEOUT = 180


class ProtocolError(Exception):
    def __init__(self, message: str):
        self.message = message


class IncomingMessage:
    def __init__(self, msg_str):
        if not isinstance(msg_str, str):
            raise TypeError('Incoming message needs to be represented as a string')

        # destructuring - will raise ValueError(not enough values to unpack...) if too few arguments
        (lr, self.sender, content_length, self.content) = msg_str.split(',', 3)

        if not lr == 'LR':
            raise ValueError('Incoming message did not start with "LR"')

        if not int(content_length, 16) == len(self.content):
            raise ValueError('Incoming message is incomplete')


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

    def is_valid_and_alive(self):
        """
        Checks if this route is valid and not expired.
        :return: True if the route is valid and it's lifetime is not expired, False otherwise
        """
        return self.is_route_valid and self.expiry_time > time.time()

    def invalidate(self):
        """Invalidates this route and sets its expiry_time to time.time() + DELETE_PERIOD"""
        self.is_route_valid = False
        self.expiry_time = time.time() + DELETE_PERIOD


def _tbytes_to_byte_str(arr: list[Tbyte]):
    """Converts an array of Tbytes into a byte-string"""
    byte_str = b''
    for i in arr:
        byte_str += i.byte_string()
    return byte_str


class Protocol:
    def __init__(self, address: str, msg_in: queue.Queue[bytes], msg_out: callable, to_display: callable):
        # from parameters
        self.address = address
        self.msg_in = msg_in
        self.msg_out = msg_out
        self.to_display = to_display

        # initialized here
        self.sequence_number = Tbyte(0)
        self.msg_id = Tbyte(255)
        self.routes: Dict[str, RouteTableEntry] = {}
        # self.reverse_routes = {}
        self.processed_messages: Dict[str, float] = {}
        self.rreq_id = Tbyte(0)
        # stores tasks to do at a certain time as tuples of (time, cmd: str, callback_func: callable, [args]
        self.timed_tasks = []
        # stores tuples of msg_type, from_address
        self.waited_for: list[tuple[int, str, Tbyte]] = []
        # stores text requests to send when a route is found. A text-request is stored as tuple(dest-addr, msg)
        self.buffered_text_requests: list[SendTextRequest] = []
        # stores blacklisted addresses (this node will not respond to RREQs forwarded from these addresses)
        self.blacklist: Dict[str, float] = {}

    def __do_check_repeat_callback(self, task):
        """
        Expects: msg_type, address, msg, repeats, callback = task[2], task[3], task[4], task[5], task[6] \n
        Checks if a message of certain 'msg_type' was received from 'address', else send 'msg' to 'address'.
        IF 'repeats' is == 0, do not send 'msg', but instead call 'callback' with argument 'msg'
        """
        msg_type, address, msg, repeats, callback = task[2:]
        try:
            found_msg = next(i for i in self.waited_for if i == (msg_type, address))
            self.waited_for.remove(found_msg)
            # "waited for" message has been received, check successful
            self.timed_tasks.remove(task)
            return
        except StopIteration:
            # no message was found -> repeat?
            if repeats.unsigned() < 0:
                # no repeats left, stop repeating
                self.to_display('info', 'message (type=' + msg_type.unsigned() + ', next_hop=' + address +
                                ') exceeded repeats, will not be repeated again.')
                self.timed_tasks.remove(task)
                if hasattr(callback, '__call__'):
                    callback(msg)
            else:
                # resend 'msg' to 'address', decrease 'repeats' by one
                repeats.decrease()
                self.msg_out(msg, address)

    def __do_timed_tasks(self):
        """
        Goes through the list of tasks to be done at a certain time and does them if they are due.
        Returns the time before the next task is due in seconds OR None if there are no tasks to be done.
        """
        if len(self.timed_tasks) == 0:
            return None

        # get all due tasks
        due_tasks = [task for task in self.timed_tasks if time.time() > task[0]]
        for task in due_tasks:
            # get the tasks command
            t_cmd = task[1]
            if t_cmd == 'send':
                msg, address = task[2, 3]
                self.msg_out(msg, address)
            elif t_cmd == 'check-repeat-callback':
                self.__do_check_repeat_callback(task)
            elif t_cmd == 'callback':
                callback, args = task[2], task[3]
                if hasattr(callback, '__call__'):
                    callback(*args)

        # return the minimum remaining time
        return min([i[0] for i in self.timed_tasks]) - time.time()

    def protocol_loop(self):
        while 1:
            # if there are timed tasks open, only block until the next task is due
            block_for_secs = self.__do_timed_tasks()
            msg_str = self.msg_in.get(timeout=block_for_secs)

            # -----------------------
            # Destructure and confirm integrity of message
            # -----------------------

            # destructuring - will raise ValueError(not enough values to unpack...) if too few arguments
            try:
                (lr, sender, content_length, content) = msg_str.split(b',', 3)
            except ValueError:
                self.to_display('error', 'Incoming message had too few separators, discarded')
                continue

            if not lr == 'LR':
                self.to_display('error', 'Incoming message did not start with "LR", discarded')
                continue

            if not int(content_length, 16) == len(content):
                self.to_display('info', 'Incoming message is incomplete, discarded')
                continue

            # -----------------------
            # evaluate msg_type and hand it to correct method
            # -----------------------
            try:
                msg_type = Tbyte(content[0]).unsigned()
                if msg_type == 1:  # RREQ
                    self.__handle_rreq(sender, list(msg_str))
                elif msg_type == 2:  # RREP
                    self.msg_out(self.construct_rrep_ack(), sender)
                    self.__handle_rrep(sender, list(msg_str))
                elif msg_type == 3:  # RERR
                    self.__handle_rerr(sender, list(msg_str))
                elif msg_type == 4:  # RREP-ACK
                    self.to_display('info', str(sender) + ' acknowledged RREP.')
                    self.waited_for.append((4, sender, Tbyte(0)))
                elif msg_type == 5:  # SEND-TEXT-REQUEST
                    # TODO Dont forget RERR in callback
                    self.__handle_s_t_r(sender, msg_str)
                elif msg_type == 6:  # SEND-HOP-ACK
                    msg_id = content[1]
                    self.to_display('info', str(sender) + ' sent SEND-HOP-ACK for message: ' + msg_id)
                    self.waited_for.append((6, sender, msg_id))
                elif msg_type == 7:  # SEND-TEXT-REQUEST-ACK
                    self.__handle_s_t_r_ack(list(msg_str))
                else:
                    self.to_display('info', 'Malformed message, discarded (Type unknown')
            except ProtocolError as e:
                self.to_display(
                    'error',
                    'Protocol violated:' + e.message +
                    '\nmessage as hex: ' + msg_str.hex(':') +
                    '\nmessage as int: ' + ', '.join(str(Tbyte(y).unsigned()) for y in msg_str)
                )

    # ----------------------------------------------------------------------------------------------
    #                                     SEND-TEXT-REQUEST
    # ----------------------------------------------------------------------------------------------

    def __handle_s_t_r(self, prev_node: str, msg_str: bytes):
        # Deconstruct msg_str
        try:
            msg_type: Tbyte
            msg_origin_addr: Tbyte
            msg_dest_addr: Tbyte
            msg_id: Tbyte
            msg_type, msg_origin_addr, msg_dest_addr, msg_id = [Tbyte(x) for x in msg_str[:3]]
            payload = msg_str[4:]
        except (ValueError, IndexError):
            raise ProtocolError('Message header has too few arguments (Type RREP)')

        # Send SEND-HOP-ACK
        self.msg_out(_tbytes_to_byte_str([Tbyte(6), msg_id]), prev_node)

        # --------------------------
        # Update Route to Origin and prev_node
        # --------------------------
        self.__max_out_lifetimes(prev_node, msg_origin_addr.address_string())

        # --------------------------
        # If I am the destination
        # --------------------------
        # TODO ignore messages i already displayed?
        if msg_dest_addr.address_string() == self.address:
            # send S-T-R-ACK
            str_ack = _tbytes_to_byte_str([Tbyte(7), msg_origin_addr, msg_dest_addr, msg_id])
            self.msg_out(str_ack, prev_node)
            # display message
            self.to_display('msg', msg_origin_addr.address_string(), msg_id, payload)
            return

        # --------------------------
        # If no active route
        # --------------------------
        route_to_dest = self.routes.get(msg_dest_addr.address_string())
        if not route_to_dest or route_to_dest.is_valid_and_alive() is False:
            # prolong DELETE_PERIOD (AODV: 6.11 2nd to last sentence):
            if route_to_dest.is_route_valid is False:
                route_to_dest.expiry_time = time.time() + DELETE_PERIOD

            # No active route to dest, send RERR TODO: What to do if dest is next hop?
            dependants = self.__invalidate_route(msg_dest_addr.address_string(), None)
            self.__send_rerr(dependants, [(msg_dest_addr, route_to_dest.dest_sequence_num)])
            return

        # --------------------------
        # Active Route exists, forward S-T-R
        # --------------------------
        # Update Routes to destination and next_hop
        self.__max_out_lifetimes(msg_dest_addr.address_string(), route_to_dest.next_hop)

        # Forward S-T-R (without changes)
        self.msg_out(msg_str, route_to_dest.next_hop)

    def send_s_t_r(self, dest_addr: str, payload: bytes, display_id: int):

        text_req = SendTextRequest(
            origin_addr=Tbyte(int(self.address)),
            dest_addr=Tbyte(int(dest_addr)),
            msg_id=self.msg_id.increase().copy(),
            payload=payload
        )

        route_to_dest = self.routes.get(text_req.dest_addr.address_string())
        assert isinstance(route_to_dest, RouteTableEntry)

        # --------------------------
        # No active route
        # --------------------------
        if not route_to_dest or not route_to_dest.is_valid_and_alive():
            # store message to send on RREP
            self.buffered_text_requests.append(text_req)
            # send RREQ (AODV: 6.3)
            self.__originate_rreq_to(text_req.dest_addr)
        # --------------------------
        # Active route
        # --------------------------
        else:
            # add callback on timeout for STR-ACK
            self.timed_tasks.append((
                time.time() + PATH_DISCOVERY_TIME,  # wait for PATH_DISCOVERY_TIME
                'callback',  # to call back
                self.__check_for_s_t_r_ack,  # this method
                [text_req.msg_id, text_req.dest_addr, display_id]  # to declare S-T-R as LOST
            ))
            # send STR for (S_T_R_REPEAT + 1) times or until SEND-HOP-ACK received
            self.__send_s_t_r_repeated(
                text_req=text_req,
                repeats=S_T_R_REPEAT
            )

    def __max_out_lifetimes(self, *dests: str):
        for dest in dests:
            route = self.routes.get(dest)
            if route:
                route.expiry_time = time.time() + DEFAULT_LIFETIME

    def __handle_s_t_r_ack(self, msg_str: list[int]):
        # Deconstruct msg_str
        try:
            msg_type: Tbyte
            msg_origin_addr: Tbyte
            msg_dest_addr: Tbyte
            msg_seq_num: Tbyte
            msg_type, msg_origin_addr, msg_dest_addr, msg_seq_num = (Tbyte(x) for x in msg_str)
        except (ValueError, IndexError):
            raise ProtocolError('Message header has too few arguments (Type RREP)')

        self.__max_out_lifetimes(msg_origin_addr.address_string(), msg_dest_addr.address_string())

        # if for me, register in waited_for so message is not declared LOST
        if msg_origin_addr.address_string() == self.address:
            self.waited_for.append((7, msg_dest_addr.address_string(), msg_seq_num))
        # else send on route
        else:
            route_to_origin = self.routes.get(msg_origin_addr.address_string())
            if route_to_origin is not None:
                self.__send_s_t_r_ack(
                    origin_addr=msg_origin_addr,
                    dest_addr=msg_dest_addr,
                    msg_seq_num=msg_seq_num,
                    next_hop=route_to_origin.next_hop
                )

    def __send_s_t_r_ack(self, origin_addr: Tbyte, dest_addr: Tbyte, msg_seq_num: Tbyte, next_hop: str):
        msg = _tbytes_to_byte_str([Tbyte(7), origin_addr, dest_addr, msg_seq_num])
        self.msg_out(msg, next_hop)

    # waits for STR-ACK
    def __check_for_s_t_r_ack(self, msg_id: Tbyte, dest_addr: Tbyte, display_id: int):
        """
        Called, when the waiting time for an S-T-R-ACK timed out. First checks for a received ACK.
        If there is none, declares the message as lost by calling self.to_display('msg-lost', :param: display_id)

        :param msg_id: ID of SEND-TEXT-REQUEST that needs to be acknowledged
        :param dest_addr: Address of Destination-Node of the SEND-TEXT-REQUEST
        :param display_id: Some identification to let the View know which message was lost
        :return: None
        """
        try:
            # if a SEND-TEXT-REQUEST-ACK from 'dest-addr' was received, message was not lost
            found_ack = next(i for i in self.waited_for if i == (7, dest_addr, msg_id))
            self.waited_for.remove(found_ack)
        except StopIteration:
            # else declare message as lost
            self.to_display('msg-lost', display_id)

    # waits for SEND-HOP-ACK
    def __send_s_t_r_repeated(self, text_req: SendTextRequest, repeats: int):
        next_hop = self.routes.get(text_req.dest_addr.address_string()).next_hop
        try:
            # if a SEND-HOP-ACK from 'address' was received, no need to send S-T-R again
            found_ack = next(i for i in self.waited_for if i == (6, next_hop, text_req.msg_id))
            self.waited_for.remove(found_ack)
        except StopIteration:
            # else send S-T-R again, if there are repeats left
            if repeats < 0:
                if text_req.origin_addr == self.address:
                    self.to_display('info', str(next_hop) + ' did not acknowledge S-T-R with id: ' +
                                    str(text_req.msg_id.unsigned()))
                # send RERR to precursors AND delete buffered messages to dest_addr
                self.__declare_next_hop_unreachable(next_hop)
                self.buffered_text_requests = [x for x in self.buffered_text_requests if x[0] != text_req.dest_addr]
            else:
                # send message
                self.msg_out(text_req.to_bytestring(), next_hop)
                # register next callback at given time
                self.timed_tasks.append((
                    time.time() + RREP_ACK_WAIT,
                    'callback',
                    self.__send_s_t_r_repeated,
                    [text_req, repeats - 1]
                ))

    # ----------------------------------------------------------------------------------------------
    #                                           RERR
    # ----------------------------------------------------------------------------------------------

    def __handle_rerr(self, prev_node: str, msg_arr: list[int]):
        try:
            msg_type: Tbyte
            msg_dest_count: Tbyte
            msg_type, msg_dest_count = [Tbyte(x) for x in msg_arr[:2]]
            # pack each dest_addr with their dest_seq_num in a tuple as Tbytes and keep them in a list
            list_of_dests = [(Tbyte(msg_arr[i]), Tbyte(msg_arr[i + 1])) for i in range(2, len(msg_arr))[::2]]
        except (ValueError, IndexError):
            raise ProtocolError('Message header has too few arguments (Type RERR)')

        # precursors that might be affected
        dependants = set()

        for x in list_of_dests:
            dest_addr, dest_seq_num = x
            dependants.update(self.__invalidate_route(dest_addr.address_string(), dest_seq_num))

        self.__send_rerr(dependants, list_of_dests)

    def __declare_next_hop_unreachable(self, unr_next_hop: str):
        """
        Unions the methods __get_affected_dests, __invalidate_route and __send_rerr to a single method.\n
        Takes a next_hop address that became unreachable, collects all routes (unr_next_hop included)
        that use it as the next hop and invalidates them, while keeping track of nodes (precursors), that
        depend on these routes.\n
        Then sends all these dependants a RERR\n

        :param unr_next_hop: neighbouring node that became unreachable
        :type unr_next_hop: str
        """
        # get affected destinations
        list_of_dests = self.__get_affected_dests(unr_next_hop)
        # invalidate routes to affected destinations
        dependants = set()
        for dest in list_of_dests:
            dependants.update(self.__invalidate_route(dest[0].address_string(), None))
        # send a RERR to possible dependants
        self.__send_rerr(dependants, list_of_dests)

    def __get_affected_dests(self, unr_next_hop: str) -> list[tuple[Tbyte, Tbyte]]:
        """
        Takes a next_hop address that became unreachable and collects all routes (unr_next_hop included)
        that use it as the next hop. Returns them as a list of tuples of (dest_addr, dest_seq_num)\n
        :param unr_next_hop: address of neighbouring node which became unreachable
        :type unr_next_hop: str
        :return: a list of unreachable destinations as tuples of (dest_addr, dest_seq_num)
        :rtype: list[tuples[Tbyte, Tbyte]]
        """
        affected_dests = []
        # append all destinations to which the next_hop became unreachable
        for route in self.routes.values():
            if route.next_hop == unr_next_hop:
                affected_dests.append((Tbyte(int(route.destination_addr)), route.dest_sequence_num))

        return affected_dests

    def __invalidate_route(self, dest_addr: str, dest_seq_num: Union[Tbyte, None]) -> set[str]:
        """
        Invalidates route to dest_addr if it exists and returns a set of all affected precursors.\n
        Sets dest_seq_num as secuence number of route. If dest_seq_num is None and if the routes sequence number
        is valid, that sequence number will be increased (see AODV: 6.11: enumeration on page 25: 1.)\n
        :param dest_addr: destination address that became unreachable
        :type dest_addr: str
        :param dest_seq_num: dest_seq_num: sequence number to update the (invalid) route with
        :type dest_seq_num: dest_seq_num: Tbyte
        :return: a set of affected precursors
        :rtype: set
        """
        dependants = set()

        # invalidate route
        route_to_dest = self.routes.get(dest_addr)
        if route_to_dest is not None:
            route_to_dest.is_route_valid = False

            if dest_seq_num is None and route_to_dest.is_dest_seq_valid:
                route_to_dest.dest_sequence_num.increase()
            else:
                route_to_dest.dest_sequence_num = dest_seq_num

            route_to_dest.expiry_time = time.time() + DELETE_PERIOD
            # remember any precursors that might be affected
            dependants.update(route_to_dest.precursors)

        return dependants

    def __send_rerr(self, dependants: set[str], list_of_dests: list[tuple[Tbyte, Tbyte]]):
        """
        Sends RERR via unicast if there is only one dependant, broadcasts if there are more.\n
        :param dependants: precursors of invalid routes to send a RERR to
        :type dependants: set[str]
        :param list_of_dests: destinations as tuples of (address, sequence_number) to include in RERR
        :type list_of_dests: list[tuple[Tbyte, Tbyte]]
        """
        dep_count = len(dependants)

        if dep_count == 0:
            return
        elif dep_count == 1:
            rerr = self.construct_rerr(list_of_dests)
            self.msg_out(rerr, dependants.pop())
        elif dep_count > 1:
            rerr = self.construct_rerr(list_of_dests)
            self.msg_out(rerr, 'FFFF')

    def construct_rerr(self, list_of_dests: list[tuple[Tbyte, Tbyte]]):
        msg_type = Tbyte(3)
        dest_count = len(list_of_dests)
        msg_arr = [msg_type, dest_count]
        for elem in list_of_dests:
            msg_arr.extend(elem)
        return _tbytes_to_byte_str(msg_arr)

    # ----------------------------------------------------------------------------------------------
    #                                      RREP & RREP-ACK
    # ----------------------------------------------------------------------------------------------

    def __handle_rrep(self, prev_node: str, msg_arr: list[int]):
        # -----------------------
        # deconstruct message-array items (message's content) as Tbytes
        # -----------------------
        try:
            msg_type: Tbyte
            msg_hop_count: Tbyte
            msg_origin_addr: Tbyte
            msg_dest_addr: Tbyte
            msg_dest_seq_num: Tbyte
            msg_lifetime: Tbyte

            msg_type, msg_hop_count, msg_origin_addr, msg_dest_addr, msg_dest_seq_num, msg_lifetime = \
                [Tbyte(x) for x in msg_arr]
        except ValueError:
            raise ProtocolError('Message header has too few arguments (Type RREP)')

        # -----------------------
        # create or get route to prev_node (AODV: 6.7 sentences 1-2)
        # -----------------------
        if self.routes.get(prev_node) is None:
            self.routes[prev_node] = RouteTableEntry(
                destination_addr=prev_node,
                dest_sequence_num=Tbyte(0),
                is_dest_seq_valid=False,
                is_route_valid=True,
                hops=Tbyte(1),
                next_hop=prev_node,
                precursors=set(),
                lifetime=time.time() + DEFAULT_LIFETIME
            )
        route_to_prev_hop = self.routes.get(prev_node)
        assert isinstance(route_to_prev_hop, RouteTableEntry)

        # increase hop count (old value will not be used)(AODV: 6.7 sentences 3-4)
        msg_hop_count.increase()

        # -----------------------
        # create or update route to RREP's destination (AODV: 6.7 sentences 1-2)
        # -----------------------

        # check if the route to RREP's destination should be updated (AODV: 6.7 (i)-(iv))
        route_to_dest = self.routes.get(msg_dest_addr.address_string())
        should_update = \
            route_to_dest is None or \
            route_to_dest.is_dest_seq_valid is False or \
            (route_to_dest.is_dest_seq_valid and msg_dest_seq_num > route_to_dest.dest_sequence_num) or \
            (route_to_dest.dest_sequence_num == msg_dest_seq_num and route_to_dest.is_route_valid is False) or \
            (route_to_dest.dest_sequence_num == msg_dest_seq_num and msg_hop_count < route_to_dest.hops)

        if should_update:
            route_to_dest = self.routes[msg_dest_addr.address_string()] = \
                RouteTableEntry(
                    destination_addr=msg_dest_addr.address_string(),
                    dest_sequence_num=msg_dest_seq_num,
                    is_dest_seq_valid=True,
                    is_route_valid=True,
                    hops=msg_hop_count,
                    next_hop=prev_node,
                    precursors=set(),
                    lifetime=time.time() + msg_lifetime.unsigned()
                )

        # if i was the RREQ's originator, processing stops here
        if msg_origin_addr.address_string() == self.address:
            for text_req in [x for x in self.buffered_text_requests if x.dest_addr == msg_dest_addr]:
                self.__send_s_t_r_repeated(
                    text_req=text_req,
                    repeats=S_T_R_REPEAT
                )

            # stop resending of RREQ by registering the RREP
            self.waited_for.append((2, msg_dest_addr.address_string(), Tbyte(0)))
            return None, None

        # -----------------------
        # SEND RREP
        # -----------------------

        # the node consults its route table entry
        #    for the originating node to determine the next hop for the RREP
        #    packet,
        route_to_origin = self.routes.get(msg_origin_addr.address_string())
        if route_to_origin is None:
            raise ValueError('Received a RREP (destination: ' + msg_dest_addr.address_string() + ') to an unknown RREQ')
        assert isinstance(route_to_origin, RouteTableEntry)

        # AODV: 6.7 last paragraph:
        # update precursor list of route_to_destination to include next_hop_to_origin
        route_to_dest.precursors.add(route_to_origin.next_hop)
        # update precursor list of route_to_origin to include next_hop_to_dest
        route_to_origin.precursors.add(route_to_dest.next_hop)
        # update expiry_time of route_to_origin
        route_to_origin.expiry_time = max(route_to_origin.expiry_time, time.time() + DEFAULT_LIFETIME)

        rrep = self.construct_rrep(
            hop_count=msg_hop_count,
            origin_addr=msg_origin_addr,
            dest_addr=msg_dest_addr,
            dest_seq_num=msg_dest_seq_num,
            lifetime=msg_lifetime
        )

        self.__send_rrep_repeated(rrep, route_to_origin.next_hop, RREP_REPEAT)

    # waits for RREP-ACK
    def __send_rrep_repeated(self, rrep: bytes, address: str, repeats: int):
        try:
            # if any RREP-ACK from 'address' was received, no need to send RREP again or blacklist
            found_ack = next(i for i in self.waited_for if i == (4, address))
            self.waited_for.remove(found_ack)
        except StopIteration:
            # if no RREP-ACK was received, send again or blacklist
            if repeats < 0:
                # display info on unreachable node
                self.to_display('info', 'RREP to ' + address + ' was not acknowledged, stop repeating.')
                # blacklist unreachable node
                self.blacklist[address] = time.time() + BLACKLIST_TIMEOUT
                # declare the node as unreachable and send RERRs
                self.__declare_next_hop_unreachable(address)
            else:
                self.to_display('info', 'RREP to ' + address + ' was not acknowledged, repeat.')
                self.msg_out(rrep, address)
                self.timed_tasks.append(
                    (time.time() + RREP_ACK_WAIT, 'callback', self.__send_rrep_repeated, [rrep, address, repeats - 1])
                )

    def construct_rrep(self, hop_count: Tbyte, origin_addr: Tbyte, dest_addr: Tbyte,
                       dest_seq_num: Tbyte, lifetime: Tbyte):
        msg_type = 2
        return _tbytes_to_byte_str([msg_type, hop_count, origin_addr, dest_addr, dest_seq_num, lifetime])

    def construct_rrep_ack(self):
        return Tbyte(4).byte_string()

    # ----------------------------------------------------------------------------------------------
    #                                           RREQ
    # ----------------------------------------------------------------------------------------------

    def __handle_rreq(self, prev_node: str, msg_arr: list[int]):
        # -----------------------
        # deconstruct message-array items (message's content) as Tbytes
        # -----------------------
        try:
            msg_type, msg_uflag, msg_hop_count, msg_rreq_id, msg_origin_addr, \
            msg_origin_seq_num, msg_dest_addr, msg_dest_seq_num = [Tbyte(x) for x in msg_arr]
        except ValueError:
            raise ProtocolError('Message header has too few arguments (Type RREQ)')

        # -----------------------
        # Create or update RouteTableEntry for previous hop (AODV: 6.5 1st paragraph)
        # -----------------------
        route_to_prev = self.routes.get(prev_node)

        if route_to_prev:
            route_to_prev.is_route_valid = True
            route_to_prev.hops = 1
            route_to_prev.next_hop = prev_node
            route_to_prev.expiry_time = time.time() + DEFAULT_LIFETIME
        else:
            self.routes[prev_node] = RouteTableEntry(
                destination_addr=prev_node,
                dest_sequence_num=Tbyte(0),
                is_dest_seq_valid=False,
                is_route_valid=True,
                hops=Tbyte(1),
                next_hop=prev_node,
                precursors=set(),
                lifetime=time.time() + DEFAULT_LIFETIME
            )

        # -----------------------
        # Decide whether to process this RREQ
        # -----------------------

        # create key to find already processed RREQs (avoid loops)
        msg_key = msg_origin_addr.address_string() + str(msg_rreq_id)
        ignore_until = self.processed_messages.get(msg_key)

        # ignore this rreq for (another) PATH_DISCOVERY_TIME seconds
        self.processed_messages[msg_key] = time.time() + PATH_DISCOVERY_TIME

        # ignore the RREQ if it's entry in ignore-list exists and is not expired
        if ignore_until and ignore_until < time.time():
            self.to_display('info', 'Got RREQ (ORIGIN_IP+RREQ_ID=' + msg_key + ') a second time, discarded')
            return

        # -----------------------
        # create or update route table entry to originator (reverse route)
        # (AODV: 6.5 2nd paragraph (without ++hop_count))
        # -----------------------
        route_to_origin = self.routes.get(msg_origin_addr.address_string())

        if route_to_origin:
            if msg_uflag == 0 and msg_dest_seq_num > route_to_origin.dest_sequence_num:
                route_to_origin.dest_sequence_num = msg_origin_seq_num
            route_to_origin.is_route_valid = True
            route_to_origin.hops = msg_hop_count
            route_to_origin.next_hop = prev_node
            route_to_origin.expiry_time = time.time() + DEFAULT_LIFETIME
        else:
            self.routes[msg_origin_addr.address_string()] = RouteTableEntry(
                destination_addr=prev_node,
                dest_sequence_num=msg_origin_seq_num,
                is_dest_seq_valid=True,
                is_route_valid=True,
                hops=msg_hop_count,
                next_hop=prev_node,
                precursors=set(),
                lifetime=time.time() + DEFAULT_LIFETIME
            )

        # -----------------------
        # SEND RREP
        # -----------------------

        # if i am the destination, answer with RREP
        # -----------------------
        if msg_dest_addr.address_string() == self.address:
            # increase my_seq_num if msg_seq_num is equal to it (AODV: 6.6.1)
            max(self.sequence_number, msg_dest_seq_num)

            origin_rrep = self.construct_rrep(
                hop_count=Tbyte(0),
                origin_addr=msg_origin_addr,
                dest_addr=Tbyte(int(self.address)),
                dest_seq_num=self.sequence_number,
                lifetime=Tbyte(DEFAULT_LIFETIME)
            )
            self.__send_rrep_repeated(origin_rrep, prev_node, RREP_REPEAT)

        # if i know a valid route to destination, answer with that route
        # -----------------------
        route_to_dest = self.routes.get(msg_dest_addr.address_string())
        # evaluate whether to send route information about destination (AODV: 6.6.(ii))
        is_no_stale_route = route_to_dest.dest_sequence_num >= msg_dest_seq_num
        if route_to_dest and route_to_dest.is_valid_and_alive() \
                and route_to_dest.is_dest_seq_valid and is_no_stale_route:
            # update precursors of forward route (AODV: 6.6.2 (2nd paragraph, 1st sentence))
            route_to_dest.precursors.add(prev_node)
            # Update next hop of reverse route entry (AODV: 6.6.2 (2nd paragraph, 2nd sentence)
            route_to_origin.next_hop = prev_node

            inter_rrep = self.construct_rrep(
                hop_count=route_to_dest.hops,
                origin_addr=msg_origin_addr,
                dest_addr=msg_dest_addr,
                dest_seq_num=route_to_dest.dest_sequence_num,
                lifetime=Tbyte(int(route_to_dest.expiry_time - time.time()))
            )
            self.__send_rrep_repeated(inter_rrep, prev_node, RREP_REPEAT)

        # -----------
        # FORWARD RREQ
        # -----------
        # if i have an (invalid) route to destination, update sequence number if mine is greater than rreq's
        # AODV: 6.5 2nd to last paragraph, 2nd to last sentence
        if route_to_dest:
            msg_dest_seq_num = max(msg_dest_seq_num, route_to_dest.dest_sequence_num)

        # update RREQ to forward (AODV: 6.5 (second to last paragraph))
        fwd_rreq = self.construct_rreq(
            hop_count=msg_hop_count.increase(),
            rreq_id=msg_rreq_id,
            origin_addr=msg_origin_addr,
            origin_seq_num=msg_origin_seq_num,
            dest_addr=msg_dest_addr,
            dest_seq_num=msg_dest_seq_num
        )

        # broadcast forwarded RREQ
        self.msg_out(fwd_rreq, 'FFFF')

    # waits for RREP TODO: increase RREQ ID
    def __send_rreq_repeated(self, rreq: RREQ, repeats: int):
        try:
            # if any RREP for 'destination-addr' was received, no need to send RREQ again
            found_rrep = next(i for i in self.waited_for if i == (2, rreq.dest_addr.address_string(), Tbyte(0)))
            self.waited_for.remove(found_rrep)
        except StopIteration:
            if repeats < 0:
                self.to_display(
                    'info', 'RREQ to ' + rreq.dest_addr.address_string() + ' timed out, no (more) repeating.'
                )
            else:
                self.to_display('info', 'Sending RREQ to ' + rreq.dest_addr.address_string() +
                                ' with ' + str(repeats) + ' repetitions.')

                # increase rreq_id and send new rreq
                self.msg_out(rreq.increase_rreq_id(), 'FFFF')

                # schedule next call
                self.timed_tasks.append((
                    time.time() + PATH_DISCOVERY_TIME,
                    'callback',
                    self.__send_rreq_repeated,
                    [rreq, repeats - 1]
                ))

    def __originate_rreq_to(self, dest_addr: Tbyte):
        route_to_dest = self.routes.get(dest_addr.address_string())

        # send RREQ (AODV: 6.3)
        dest_seq_num = None \
            if route_to_dest is None or route_to_dest.is_dest_seq_valid is False \
            else route_to_dest.dest_sequence_num

        rreq = RREQ(
            hop_count=Tbyte(0),
            rreq_id=self.rreq_id.increase().copy(),
            origin_addr=Tbyte(int(self.address)),
            origin_seq_num=self.sequence_number.increase(),
            dest_addr=dest_addr,
            dest_seq_num=dest_seq_num
        )

        # send RREQ 3 times or until RREP received TODO: add callback if repeat == 0?
        self.__send_rreq_repeated(rreq, RREQ_REPEAT)
