from __future__ import annotations

import _thread
import queue
import random
import sys
import time

from typing import Dict, Optional

from Util import Tbyte, SendTextRequest, RREQ, ProtocolError, RouteTableEntry, TimedTask

# default expiry_time of a route until it becomes invalid (sec)
DEFAULT_LIFETIME = 180
# Time in secs to wait for RREP or S-T-R-ACK
PATH_DISCOVERY_TIME = 30
# Number of repetitions if no answer was received
MSG_REPEATS = 2
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


# time in seconds to wait for a RREP-ACK before resending RREP / blacklisting or giving up
def rrep_ack_wait() -> int:
    return random.randint(4, 6)


def _tbytes_to_byte_str(arr: list[Tbyte]):
    """Converts an array of Tbytes into a byte-string"""
    byte_str = b''
    for i in arr:
        byte_str += i.byte_string()
    return byte_str


class Protocol:
    def __init__(self, address: str, msg_in: queue.Queue[bytes], msg_out: callable, to_display: callable):
        # from parameters
        # ----------------
        # address of this module
        self.address = address
        # queue to get incoming messages from (processed in protocol_loop())
        self.msg_in = msg_in
        # function to send messages (expect args: msg, address)
        self.msg_out = msg_out
        # function to display messages and other communication (like errors or info)
        self.to_display = to_display

        # initialized here
        # ----------------
        # sequence number of this module
        self.sequence_number = Tbyte(0)
        # msg_id for s-t-r's to identify on ACK
        self.msg_id = Tbyte(255)
        # route table
        self.routes: Dict[str, RouteTableEntry] = {}
        # already processed messages (RREQs only atm)
        self.processed_messages: Dict[str, float] = {}
        # current RREQ_id to identify each resend of same RREQ
        self.rreq_id = Tbyte(0)
        # stores tasks to do at a certain time as tuples of (time, cmd: str, callback_func: callable, [args]
        self.timed_tasks: list[TimedTask] = []
        # stores tuples of msg_type, from_address
        self.waited_for: list[tuple[int, str, Tbyte]] = []
        # stores text requests to send when a route is found. A text-request is stored as tuple(dest-addr, msg)
        self.buffered_text_requests: list[SendTextRequest] = []
        # stores blacklisted addresses (this node will not respond to RREQs forwarded from these addresses)
        self.blacklist: Dict[str, float] = {}

    def __do_timed_tasks(self):
        """
        Goes through the list of tasks to be done at a certain time and does them if they are due.
        Returns the time before the next task is due in seconds OR None if there are no tasks to be done.
        """
        if len(self.timed_tasks) == 0:
            return None

        # get all due tasks
        due_tasks = [task for task in self.timed_tasks if task.is_due()]
        for task in due_tasks:
            # call back given callback with given args
            task.callback(*task.args)
            # remove done tasks
            self.timed_tasks.remove(task)

        # return the minimum remaining time if there are tasks else return none
        return min([i.time_to_call for i in self.timed_tasks]) - time.time() if len(self.timed_tasks) > 0 else None

    def __delete_expired_routes(self):
        """
        Deletes routes that are marked as invalid and have an expired lifetime (DELETE_PERIOD).
        This function serves to clean up tables, RRERs will only be sent on attempted usages.
        """
        to_delete = [x for x in self.routes.keys() if self.routes[x].to_delete()]
        for d_route in to_delete:
            self.to_display(
                'info', 'Deleted route to ' + self.routes.pop(d_route).destination_addr + '. DELETE_PERIOD expired.')

    def __invalidate_expired_routes(self):
        """
        Invalidates routes that are marked as valid and have an expired lifetime.
        This function serves to clean up tables, RRERs will only be sent on attempted usages.
        """
        to_invalidate = [
            x for x in self.routes.keys() if self.routes[x].is_route_valid and self.routes[x].expiry_time < time.time()
        ]
        for i_route in to_invalidate:
            self.to_display(
                'info', 'Invalidated route to ' + self.routes[i_route].destination_addr + '. Route expired.')
            self.routes[i_route].invalidate(DELETE_PERIOD)

    def __delete_buffered_messages_to(self, dest_addr: Tbyte):
        """declares all buffered messages to dest_addr as lost"""
        lost_msgs = [x for x in self.buffered_text_requests if x.dest_addr == dest_addr]
        for text_req in lost_msgs:
            self.to_display('msg-state', text_req.display_id, dest_addr.address_string(), 'LOST')
            self.buffered_text_requests.remove(text_req)

    def protocol_loop(self):
        while 1:
            # invalidate expired routes which are still marked as valid
            self.__invalidate_expired_routes()
            # delete routes that are marked as invalid and their DELETE_PERIOD expired
            self.__delete_expired_routes()

            # do timed tasks and only block until the next task is due (or indefinite if there is no task due)
            block_for_secs = self.__do_timed_tasks()
            block_for_secs = max(block_for_secs, 0) if block_for_secs else None
            try:
                # get the next message
                msg_str = self.msg_in.get(timeout=block_for_secs)
            except queue.Empty:
                # if there was no massage available in time until next task is due, do due tasks
                self.to_display('debug-out', 'Exited blocking on queue to do tasks')
                continue

            # if there were outside threads registering timed tasks, they will send this command
            if msg_str == b'do_tasks':
                continue

            # -----------------------
            # Destructure and confirm integrity of message
            # -----------------------

            # destructure incoming message
            try:
                lr: bytes
                sender: bytes
                content_length: bytes
                content: bytes
                lr, sender, content_length, content = msg_str.split(b',', 3)
            except ValueError:
                self.to_display('error', 'Incoming message had too few separators, discarded')
                continue

            # make sure it was a message
            if not lr == b'LR':
                self.to_display('error', 'Incoming message did not start with "LR", discarded')
                continue

            # make sure the message is complete
            if not int(content_length.decode('ascii'), base=16) == len(content):
                self.to_display('info', 'Incoming message is incomplete, discarded')
                continue

            sender: str = sender.decode('ascii')

            # -----------------------
            # evaluate msg_type and hand it to correct method
            # -----------------------
            try:
                msg_type = Tbyte(content[0]).unsigned()
                # RREQ
                if msg_type == 1:
                    self.__handle_rreq(sender, list(content))

                # RREP
                elif msg_type == 2:
                    self.msg_out(self.construct_rrep_ack(), sender)
                    self.__handle_rrep(sender, list(content))

                # RERR
                elif msg_type == 3:
                    self.__handle_rerr(sender, list(content))

                # RREP-ACK
                elif msg_type == 4:
                    self.to_display('info', f'{sender} acknowledged RREP.')
                    self.waited_for.append((4, sender, Tbyte(0)))

                # SEND-TEXT-REQUEST
                elif msg_type == 5:
                    self.__handle_s_t_r(sender, content)

                # SEND-HOP-ACK
                elif msg_type == 6:
                    msg_id = Tbyte(content[1])
                    self.to_display('info', f'{sender} sent SEND-HOP-ACK for message: {msg_id.unsigned()}')
                    self.waited_for.append((6, sender, msg_id))

                # SEND-TEXT-REQUEST-ACK
                elif msg_type == 7:
                    self.__handle_s_t_r_ack(list(content))

                # Unknown message type
                else:
                    self.to_display('info', 'Malformed message, discarded (Type unknown')
            except ProtocolError as e:
                self.to_display(
                    'error',
                    f'Protocol violated: {e.message}' +
                    f'\nmessage as hex: {content.hex(":")}' +
                    f'\nmessage as int: {", ".join(str(Tbyte(x).unsigned()) for x in content)}'
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

        # debug log message
        self.to_display(
            'debug-in', f'Got STR {msg_id} from {msg_origin_addr.address_string()} to {msg_dest_addr.address_string()}'
        )

        # Send SEND-HOP-ACK
        self.msg_out(_tbytes_to_byte_str([Tbyte(6), msg_id]), prev_node)
        # debug log sending of S-H-A
        self.to_display(
            'debug-out', f'Sent SHA for msg {msg_id} to {prev_node} to {msg_dest_addr.address_string()}'
        )

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
            self.to_display('msg-in', payload, msg_origin_addr.address_string())
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
            # if no route is known, set dest_seq_num to 0
            dest_seq_num = route_to_dest.dest_sequence_num if route_to_dest else Tbyte(0)
            self.__send_rerr(dependants, [(msg_dest_addr, dest_seq_num)])
            return

        # --------------------------
        # Active Route exists, forward S-T-R
        # --------------------------
        # Update Routes to destination and next_hop
        self.__max_out_lifetimes(msg_dest_addr.address_string(), route_to_dest.next_hop)

        # Forward S-T-R (without changes)
        self.msg_out(msg_str, route_to_dest.next_hop)
        # debug log forwarding
        self.to_display(
            'debug-out', f'Forwarded STR {msg_id} to {route_to_dest.next_hop}'
        )

    def send_s_t_r(self, dest_addr: str, payload: bytes, display_id: int):

        text_req = SendTextRequest(
            origin_addr=Tbyte(int(self.address)),
            dest_addr=Tbyte(int(dest_addr)),
            msg_id=self.msg_id.increase().copy(),
            payload=payload,
            display_id=display_id
        )

        route_to_dest = self.routes.get(text_req.dest_addr.address_string())

        # --------------------------
        # No active route
        # --------------------------
        if not route_to_dest or not route_to_dest.is_valid_and_alive():
            # store message to send on RREP
            self.buffered_text_requests.append(text_req)
            # send RREQ (AODV: 6.3)
            self.__originate_rreq_to(text_req.dest_addr)
            # display message as pending
            self.to_display('msg-state', display_id, dest_addr, 'PENDING')
        # --------------------------
        # Active route
        # --------------------------
        else:
            self.__do_send_s_t_r(text_req)

        # since this is a function used by other threads, get protocol_loop-thread out of blocking on msg_in.get()
        self.msg_in.put(b'do_tasks')

    def __do_send_s_t_r(self, text_req: SendTextRequest):
        # add callback on timeout for STR-ACK
        self.timed_tasks.append(TimedTask(
            time_to_call=time.time() + PATH_DISCOVERY_TIME,  # wait for PATH_DISCOVERY_TIME
            task_type='send-text-request',  # to call back
            callback=self.__check_for_s_t_r_ack,  # this method
            args=[text_req.msg_id, text_req.dest_addr, text_req.display_id]  # to declare S-T-R as LOST
        ))
        self.__send_s_t_r_repeated(
            text_req=text_req,
            repeats=S_T_R_REPEAT
        )
        self.to_display('msg-state', text_req.display_id, text_req.dest_addr.address_string(), 'SENT')

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
            msg_id: Tbyte
            msg_type, msg_origin_addr, msg_dest_addr, msg_id = (Tbyte(x) for x in msg_str)
        except (ValueError, IndexError):
            raise ProtocolError('Message header has too few arguments (Type RREP)')

        self.__max_out_lifetimes(msg_origin_addr.address_string(), msg_dest_addr.address_string())

        # if for me
        if msg_origin_addr.address_string() == self.address:
            # send info to_display
            self.to_display(
                'info', f'{msg_dest_addr.address_string()} sent STR-ACK for message {msg_id.unsigned()}'
            )
            # register in waited_for so message is not declared LOST
            self.waited_for.append((7, msg_dest_addr.address_string(), msg_id))

            # get display_id from timed task message to signal acknowledgement to_display
            buffered_display_id = next(
                (
                    x.args[2] for x in self.timed_tasks
                    if x.task_type == 'send-text-request'
                    and x.args[0] == msg_id
                    and x.args[1] == msg_dest_addr
                ),
                None
            )
            if buffered_display_id:
                self.to_display('msg-state', buffered_display_id, msg_dest_addr.address_string(), 'ACKNOWLEDGED')

        # else send on route
        else:
            route_to_origin = self.routes.get(msg_origin_addr.address_string())
            if route_to_origin is not None:
                self.__send_s_t_r_ack(
                    origin_addr=msg_origin_addr,
                    dest_addr=msg_dest_addr,
                    msg_seq_num=msg_id,
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
            found_ack = next(i for i in self.waited_for if i == (7, dest_addr.address_string(), msg_id))
            self.waited_for.remove(found_ack)
        except StopIteration:
            # else declare message as lost
            self.to_display(
                'info',
                f'Message {msg_id.unsigned()} has not been acknowledged by destination {dest_addr.address_string()}'
            )
            self.to_display('msg-state', display_id, dest_addr.address_string(), 'LOST')

    # waits for SEND-HOP-ACK
    def __send_s_t_r_repeated(self, text_req: SendTextRequest, repeats: int):
        next_hop = self.routes.get(text_req.dest_addr.address_string()).next_hop
        try:
            # if a SEND-HOP-ACK from 'address' was received, no need to send S-T-R again
            found_ack = next(i for i in self.waited_for if i == (6, next_hop, text_req.msg_id))
            self.waited_for.remove(found_ack)
            # TODO: search for RERRs as well??
            # if route is now invalid, resending doesn't make sense, possibly there was a RERR
        except StopIteration:
            # else send S-T-R again, if there are repeats left
            if repeats < 0:
                if text_req.origin_addr.address_string() == self.address:
                    self.to_display(
                        'info', f'{next_hop} did not acknowledge S-T-R with id: {text_req.msg_id.unsigned()}'
                    )
                # send RERR to precursors
                self.__declare_next_hop_unreachable(next_hop)
                # delete buffered messages to dest_addr
                self.to_display(
                    'info', f'Message {text_req.msg_id.unsigned()} has not been acknowledged by next_hop {next_hop}'
                )
                self.__delete_buffered_messages_to(text_req.dest_addr)
            else:
                # send message
                self.msg_out(text_req.to_bytestring(), next_hop)
                # register next callback at given time
                self.timed_tasks.append(TimedTask(
                    time_to_call=time.time() + rrep_ack_wait(),
                    task_type='send-text-request',
                    callback=self.__send_s_t_r_repeated,
                    args=[text_req, repeats - 1]
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

    def __invalidate_route(self, dest_addr: str, dest_seq_num: Optional[Tbyte]) -> set[str]:
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

        route_to_dest = self.routes.get(dest_addr)
        if route_to_dest is not None:

            # invalidate route
            route_to_dest.invalidate(DELETE_PERIOD)

            # in cases (i) and (ii) of AODV 6.11 dest_seq_num should be none
            if dest_seq_num is None and route_to_dest.is_dest_seq_valid:
                route_to_dest.dest_sequence_num.increase()
            # if it is not None, update own route, since it is probably fresher
            elif dest_seq_num is not None:
                route_to_dest.dest_sequence_num = dest_seq_num

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
        dest_count = Tbyte(len(list_of_dests))
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

        # if i was the RREQ's originator, send buffered text_requests
        if msg_origin_addr.address_string() == self.address:
            for text_req in [x for x in self.buffered_text_requests if x.dest_addr == msg_dest_addr]:
                self.__do_send_s_t_r(text_req)

            # stop resending of RREQ by registering the RREP
            self.waited_for.append((2, msg_dest_addr.address_string(), Tbyte(0)))
            return

        # -----------------------
        # SEND RREP
        # -----------------------

        # search reverse route for next_hop to origin (should exist)
        route_to_origin = self.routes.get(msg_origin_addr.address_string())
        if route_to_origin is None:
            self.to_display(
                'error', 'Received a RREP (destination: ' + msg_dest_addr.address_string() + ') to an unknown RREQ')
            return

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
            found_ack = next(i for i in self.waited_for if i == (4, address, Tbyte(0)))
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
                self.to_display('info', f'Sending RREP to {address}, {repeats} repetitions left.')
                self.msg_out(rrep, address)
                self.timed_tasks.append(TimedTask(
                    time_to_call=time.time() + rrep_ack_wait(),
                    task_type='rrep',
                    callback=self.__send_rrep_repeated,
                    args=[rrep, address, repeats - 1]
                ))

    def construct_rrep(self, hop_count: Tbyte, origin_addr: Tbyte, dest_addr: Tbyte,
                       dest_seq_num: Tbyte, lifetime: Tbyte):
        msg_type = Tbyte(2)
        return _tbytes_to_byte_str([msg_type, hop_count, origin_addr, dest_addr, dest_seq_num, lifetime])

    def construct_rrep_ack(self):
        return Tbyte(4).byte_string()

    # ----------------------------------------------------------------------------------------------
    #                                           RREQ
    # ----------------------------------------------------------------------------------------------

    def __handle_rreq(self, prev_node: str, msg_arr: list[int]):

        # -----------------------
        # Ignore this RREQ if prev_node is blacklisted
        # -----------------------
        blacklisted_for = self.blacklist.get(prev_node)
        if blacklisted_for and blacklisted_for > time.time():
            return

        # -----------------------
        # deconstruct message-array items (message's content) as Tbytes
        # -----------------------
        try:
            msg_rreq = RREQ(*[Tbyte(x) for x in msg_arr[1:]])
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
        msg_key = f'{msg_rreq.origin_addr.address_string()}{msg_rreq.rreq_id}{msg_rreq.origin_seq_num.unsigned()}'
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
        route_to_origin = self.routes.get(msg_rreq.origin_addr.address_string())

        if route_to_origin:
            if msg_rreq.u_flag.unsigned() == 0 and msg_rreq.dest_seq_num > route_to_origin.dest_sequence_num:
                route_to_origin.dest_sequence_num = msg_rreq.origin_seq_num
            route_to_origin.is_route_valid = True
            route_to_origin.hops = msg_rreq.hop_count
            route_to_origin.next_hop = prev_node
            route_to_origin.expiry_time = time.time() + DEFAULT_LIFETIME
        else:
            self.routes[msg_rreq.origin_addr.address_string()] = RouteTableEntry(
                destination_addr=msg_rreq.origin_addr.address_string(),
                dest_sequence_num=msg_rreq.origin_seq_num,
                is_dest_seq_valid=True,
                is_route_valid=True,
                hops=msg_rreq.hop_count,
                next_hop=prev_node,
                precursors=set(),
                lifetime=time.time() + DEFAULT_LIFETIME
            )

        # -----------------------
        # SEND RREP
        # -----------------------

        # if i am the destination, answer with RREP
        # -----------------------
        if msg_rreq.dest_addr.address_string() == self.address:
            # increase my_seq_num if msg_seq_num is equal to it (AODV: 6.6.1) TODO: unsure about this part
            max(self.sequence_number, msg_rreq.dest_seq_num)

            origin_rrep = self.construct_rrep(
                hop_count=Tbyte(0),
                origin_addr=msg_rreq.origin_addr,
                dest_addr=Tbyte(int(self.address)),
                dest_seq_num=self.sequence_number,
                lifetime=Tbyte(DEFAULT_LIFETIME)
            )
            self.__send_rrep_repeated(origin_rrep, prev_node, RREP_REPEAT)
            return

        # if i know a valid route to destination, answer with that route
        # -----------------------
        route_to_dest = self.routes.get(msg_rreq.dest_addr.address_string())
        # evaluate whether to send route information about destination (AODV: 6.6.(ii))
        if route_to_dest \
                and route_to_dest.is_valid_and_alive() \
                and route_to_dest.is_dest_seq_valid \
                and route_to_dest.dest_sequence_num >= msg_rreq.dest_seq_num:
            # update precursors of forward route (AODV: 6.6.2 (2nd paragraph, 1st sentence))
            route_to_dest.precursors.add(prev_node)
            # Update next hop of reverse route entry (AODV: 6.6.2 (2nd paragraph, 2nd sentence)
            route_to_origin.next_hop = prev_node

            inter_rrep = self.construct_rrep(
                hop_count=route_to_dest.hops,
                origin_addr=msg_rreq.origin_addr,
                dest_addr=msg_rreq.dest_addr,
                dest_seq_num=route_to_dest.dest_sequence_num,
                lifetime=Tbyte(int(route_to_dest.expiry_time - time.time()))
            )
            self.__send_rrep_repeated(inter_rrep, prev_node, RREP_REPEAT)
            return

        # -----------
        # FORWARD RREQ
        # -----------
        # if i have an (invalid) route to destination, update sequence number if mine is greater than rreq's
        # AODV: 6.5 2nd to last paragraph, 2nd to last sentence
        if route_to_dest:
            msg_rreq.dest_seq_num = max(msg_rreq.dest_seq_num, route_to_dest.dest_sequence_num)

        # update RREQ to forward (AODV: 6.5 (second to last paragraph))
        msg_rreq.hop_count.increase()

        # broadcast forwarded RREQ
        self.msg_out(msg_rreq.to_bytestring(), 'FFFF')

    def __send_rreq_repeated(self, rreq: RREQ, repeats: int):
        try:
            # if any RREP for 'destination-addr' was received, no need to send RREQ again
            found_rrep = next(i for i in self.waited_for if i == (2, rreq.dest_addr.address_string(), Tbyte(0)))
            self.waited_for.remove(found_rrep)
        except StopIteration:
            if repeats < 0:
                self.to_display(
                    'info', f'RREQ to {rreq.dest_addr.address_string()} timed out, no (more) repeating.'
                )
                # delete buffered messages that have dest_addr == rreq.dest_addr
                self.__delete_buffered_messages_to(rreq.dest_addr)

            else:
                self.to_display(
                    'info', f'Sending RREQ to {rreq.dest_addr.address_string()} with {repeats} repetitions.'
                )

                # increase rreq_id and send new rreq
                self.msg_out(rreq.increase_rreq_id().to_bytestring(), 'FFFF')

                # schedule next call
                self.timed_tasks.append(TimedTask(
                    time_to_call=time.time() + PATH_DISCOVERY_TIME,
                    task_type='rreq',
                    callback=self.__send_rreq_repeated,
                    args=[rreq, repeats - 1]
                ))

    def __originate_rreq_to(self, dest_addr: Tbyte):
        """
        Originates RREQ if there is not already one in repetition
        :param dest_addr:
        :type dest_addr:
        :return:
        :rtype:
        """

        # if there is any RREQ for the destination running, do not send rreq
        if next((x for x in self.timed_tasks if x.task_type == 'rreq' and x.args[0].dest_addr == dest_addr), None):
            self.to_display('info', 'RREQ to ' + dest_addr.address_string() + ' already running, did not send again.')
            return

        # get route to destination if it exists
        route_to_dest = self.routes.get(dest_addr.address_string())

        # send RREQ (AODV: 6.3)
        dest_seq_num = Tbyte(0)
        u_flag = Tbyte(1)
        if route_to_dest and route_to_dest.is_dest_seq_valid:
            dest_seq_num = route_to_dest.dest_sequence_num
            u_flag = Tbyte(0)

        rreq = RREQ(
            u_flag=u_flag,
            hop_count=Tbyte(0),
            rreq_id=self.rreq_id.increase().copy(),  # copy to not get updated in repetitions
            origin_addr=Tbyte(int(self.address)),
            origin_seq_num=self.sequence_number.increase().copy(),  # copy to not get updated in repetitions
            dest_addr=dest_addr,
            dest_seq_num=dest_seq_num  # No problem if updated
        )

        # send RREQ 3 times or until RREP received
        self.__send_rreq_repeated(rreq, RREQ_REPEAT)


if __name__ == '__main__':

    msg_to_prot = queue.Queue()

    prot = Protocol(
        address='0004',
        msg_in=msg_to_prot,
        msg_out=lambda msg_out, addr: print('\n-------------Message_out-------------\nTo ' +
                                            f'{addr}: {list(msg_out)}' +
                                            '\n-------------------------------------\n'),
        to_display=lambda cmd, msg_display, address=None: print('\n-------------' + cmd + '-------------\n' +
                                                                f'{msg_display}' +
                                                                '\n--------------------------' + (
                                                                        '-' * len(cmd)) + '\n')
    )

    try:
        _thread.start_new_thread(prot.protocol_loop, ())
    except (SystemExit, Exception):
        sys.exit()

    rreq_str = RREQ(
        u_flag=Tbyte(1),
        hop_count=Tbyte(2),
        rreq_id=Tbyte(0),
        origin_addr=Tbyte(6),
        origin_seq_num=Tbyte(1),
        dest_addr=Tbyte(2),
        dest_seq_num=Tbyte(1)
    ).to_bytestring()

    # -------------rreq
    msg = b'LR,0005,' + bytes(str(len(rreq_str)).encode('ascii')) + b',' + rreq_str
    msg_to_prot.put(msg)

    # -------------rrep
    time.sleep(3)
    rrep_test = b'LR,0003,6,' + \
                b'\x02' + \
                b'\x05' + \
                b'\x06' + \
                b'\x02' + \
                b'\xfe' + \
                b'\xB4'
    msg_to_prot.put(rrep_test)

    # -------------rrep-ack
    time.sleep(6)
    rrep_ack = b'LR,0005,1,' + b'\x04'
    msg_to_prot.put(rrep_ack)

    # send two messages to 6
    prot.send_s_t_r('0006', bytes('Hallo'.encode('ascii')), 0)
    prot.send_s_t_r('0006', bytes('wie geht\'s'.encode('ascii')), 1)

    # acknowledge both messages from next_hop
    time.sleep(6)
    msg_to_prot.put(b'LR,0005,2,\x06\x00')
    time.sleep(6)
    msg_to_prot.put(b'LR,0005,2,\x06\x01')

    # acknowledge only first message from destination
    time.sleep(3)
    msg_to_prot.put(b'LR,0005,4,\x07\x04\x06\x00')

    stop = ''
    while stop != 'q':
        stop = input()
        bla = ''
        for y in prot.routes.keys():
            bla += str(y) + ': ' + str(prot.routes.get(y)) + '\n'
        print(bla)
