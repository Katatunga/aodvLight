from __future__ import annotations

import sys
import threading
import time
from typing import Union, Optional

import serial
import _thread
import queue
import RPi.GPIO as GPIO

from LoRaUI import LoRaUI
# from Protocol import Protocol

# often used strings
from Protocol import Protocol

AT_OK = b'AT,OK'
LINEBREAK = b'\r\n'

# block for x seconds to wait for the answer to a command
wait_secs_for_uart_answer = 5
# sleep for x seconds to send next command
wait_secs_to_next_cmd = 0.5
# send hello every x seconds
hello_secs = 10

cmd_out = queue.Queue()
cmd_in = queue.Queue()
msg_in = queue.Queue()


class LoRaError(Exception):
    pass


class CmdAndAnswers:
    def __init__(self, cmd: bytes, answers: Union[tuple[bytes, ...], bytes], callback=None):
        # make sure cmd ends with LINEBREAK
        self.cmd = cmd if cmd.endswith(LINEBREAK) else cmd + LINEBREAK
        # make sure answers is iterable
        self.answers = answers if isinstance(answers, tuple) else (answers,)

        self.callback = callback


class LoRaController:
    def __init__(self, address: bytes = b'0004',
                 show_debug: bool = True, show_log: bool = True, show_info: bool = True):
        self.address = address

        # Display Debug
        self.show_debug_in = self.show_debug_out = show_debug
        # Display Logging
        self.show_log_in = self.show_log_out = show_log
        # Display Infos
        self.show_info = show_info

        # lock to use for synchronized sequential job-queueing
        self.lock = threading.RLock()

    # write to cmd_out queue to send a message (AT+SEND)
    def send_message(self, msg: bytes, address: Union[bytes, str]):
        # if address was passed as a string, encode it as ascii
        if isinstance(address, str):
            if address.isascii():
                address = address.encode('ascii')
            else:
                self.display_protocol('error', f'Address {address}) was not ASCII-encoded, discarded.')
                return

        # define callback for when the message was sent TODO: may be impractical
        def print_msg_sent(answer):
            if answer == 'AT,SENDED':
                self.display_protocol('msg-out', str(msg), str(address))

        # queue commands in order, so that there is no interruption by other threads
        send_cmds = list()
        send_cmds.append(CmdAndAnswers(b'AT+DEST=' + address, AT_OK))
        send_cmds.append(CmdAndAnswers(b'AT+SEND=' + str(len(msg)).encode('ascii'), AT_OK))
        send_cmds.append(CmdAndAnswers(msg, (b'AT,SENDING', b'AT,SENDED'), print_msg_sent))
        self.to_out_queue(send_cmds)

    def to_out_queue(self, cmds_and_answers: list[CmdAndAnswers]):
        """
        Writes (multiple) commands to cmd_out queue (synchronized)
        :param cmds_and_answers: commands to write to uart and answers to expect
        :type cmds_and_answers: CmdAndAnswers
        """
        # synchronize (for sequential puts)
        with self.lock:
            for elem in cmds_and_answers:
                # put command and expected answer(s) into queue
                cmd_out.put(elem)

    def write_msg_out_loop(self):
        """ write the commands in cmd_out queue to uart, then wait for and handle the answers in cmd_in """
        while 1:
            # get next command and expected answer(s) (as instance of CmdAndAnswers)
            cmd_and_answers = cmd_out.get(True)

            # break loop on command
            if cmd_and_answers == b'break':
                break

            # make sure cmd_and_answers is of type CmdAndAnswers
            if not isinstance(cmd_and_answers, CmdAndAnswers):
                raise TypeError('Did not use correct class to represent command')

            # write command to uart
            ser.write(cmd_and_answers.cmd)

            # debug log outgoing commands
            self.display_protocol('debug-out', str(cmd_and_answers.cmd.rstrip(LINEBREAK)))

            # for each expected answer
            for elem in cmd_and_answers.answers:
                try:
                    # get the actual answer (and strip off LINEBREAK)
                    answer = cmd_in.get(True, timeout=wait_secs_for_uart_answer)

                    # break loop on command
                    if answer == b'break':
                        break

                    answer = bytes(answer).rstrip(LINEBREAK)

                    # debug log answer
                    self.display_protocol('debug-in', str(answer))

                    # if actual answer is not the expected answer (should not happen), raise error
                    if elem is not None and answer != elem:
                        self.handle_errors(b'"' + cmd_and_answers.cmd + b'" was not answered with "' +
                                           elem + b'", but instead with "' + answer + b'"')

                    # if cmd_and_answers contains a callback, call it with the actual answer
                    if cmd_and_answers.callback:
                        cmd_and_answers.callback(answer)

                except queue.Empty:
                    self.handle_errors(
                        b'Got no answer to command "' + bytes(cmd_and_answers.cmd.rstrip(LINEBREAK)) + b'"')

            # wait a little to avoid CPU_busy error TODO: TEST: may not be needed since we waited for answer
            # time.sleep(wait_secs_to_next_cmd)

    def display_protocol(self, cmd: str, msg: Union[str, int, bytes], address: Optional[str] = None,
                         state: Optional[str] = None) -> Optional[int]:
        """
        Protocol machine for communication from aodv-protocol to GUI. The 'msg' is displayed according
        to the 'cmd'. However, if the 'cmd' is ['msg-lost','msg-sent','msg-ack'], 'msg' should only consist of the
        display_id, which identifies the message to update the state on.\n
        :param cmd: what type of message is msg: (msg-lost, msg-sent, msg_ack, info, debug, error, msg)
        :type cmd: str
        :param msg: message to display or display_id of lost message
        :type msg: str
        :param address: optional parameter that has to be given when cmd is 'msg' or 'msg-state' and contains the address
            of the sender
        :type address: str
        :param state: optional parameter that has to be given when cmd is 'msg-state' and contains the address
            of the sender
        :type state: str
        """

        result = None

        try:
            if isinstance(msg, bytes):
                if msg.isascii():
                    msg = msg.decode('ascii')
                else:
                    raise ValueError('Message is non ascii, will not be displayed')

            if cmd == 'msg-state':
                # update the state of the message as LOST
                if address:
                    win.update_message_state(address, msg, state)

            elif cmd == 'msg-in':
                result = win.write_to_messages(msg, address, False)
            elif cmd == 'msg-out':
                result = win.write_to_messages(msg, address, True)

            elif cmd == 'log-in':
                if self.show_log_in:
                    win.write_to_logs(msg)
            elif cmd == 'log-out':
                if self.show_log_out:
                    win.write_to_logs(msg, True)

            elif cmd == 'debug-in':
                if self.show_debug_in:
                    win.write_to_logs(msg)
            elif cmd == 'debug-out':
                if self.show_debug_out:
                    win.write_to_logs(msg, True)

            elif cmd == 'info':
                if self.show_info:
                    win.write_info(msg)

            elif cmd == 'error':
                win.write_error(msg)

            else:
                raise ValueError(f'Command {cmd} unknown')

        except (TypeError, ValueError) as e:
            win.write_error(f'Display protocol violated:'
                            f'\nErrormessage: {str(e)}'
                            f'\nParameters: cmd={cmd}, msg={msg}, address={address}, state={state}')

        return result

    def send_via_protocol(self, msg: str, address: str):
        display_id = self.display_protocol('msg-out', msg, address)

        if address == 'FFFF':
            self.display_protocol('msg-state', display_id, address=address, state='ERROR: address "FFFF" invalid')
            self.display_protocol('error', f'User tried to send Message ({msg}) to address "FFFF", discarded.')
            return
        elif not msg.isascii():
            self.display_protocol('msg-state', display_id, address=address, state='ERROR: Non-ascii')
            self.display_protocol('error', f'Message ({msg}) was not ASCII-encoded, discarded.')
            return
        else:
            protocol.send_s_t_r(
                dest_addr=address,
                payload=msg.encode('ascii'),
                display_id=display_id
            )

    def handle_user_commands(self, cmd: str, address: str):
        if cmd == 'table':
            table = ''
            for y in protocol.routes.keys():
                table += f'{y}: {protocol.routes.get(y)}\n'
            print(table)
        if cmd == 'log-in':
            self.show_log_in = not self.show_log_in
        if cmd == 'log-out':
            self.show_log_out = not self.show_log_out
        if cmd == 'debug-in':
            self.show_debug_in = not self.show_debug_in
        if cmd == 'debug-out':
            self.show_debug_out = not self.show_debug_out
        if cmd == 'info':
            self.show_info = not self.show_info

    def handle_errors(self, err_msg: bytes):
        if err_msg == b'ERR: CPU_BUSY':
            self.display_protocol('error', f'Got: "{err_msg.decode("ascii")}". Reset module.')
            reset_module()
        else:
            self.display_protocol('error', err_msg.decode('ascii'))

    def read_uart_to_protocol_loop(self):
        while 1:
            # start with an empty string to put the message in
            msg = b''
            # block until there is something received
            msg += ser.read()
            # block to read until LINEBREAK (can naturally be sent if LR, so read until content_length, see below)
            while not msg.endswith(LINEBREAK):
                msg += ser.read()

            # remove LINEBREAK
            msg = msg.rstrip(LINEBREAK)

            # handle actual messages from outside
            if msg.startswith(b'LR'):
                # if message incomplete, read rest
                msg_arr = msg.split(b',', 3)
                expected_length = int(msg_arr[2].decode('ascii'), base=16)
                if len(msg_arr[3]) < expected_length:
                    # reattach LINEBREAK which apparently was part of message
                    msg += LINEBREAK
                    # read remaining bytes of content (minus the LINEBREAK in message)
                    msg += ser.read(expected_length - 2 - len(msg_arr[3]))
                    # remove following LINEBREAK from input
                    ser.read(2)
                # handle_incoming_msg(msg)
                msg_in.put(msg)

            # handle answers to commands (put them in a queue). 'Vendor' just to deal properly with AT+RST
            elif msg.startswith(b'Vendor') or msg.startswith(b'AT') and not msg.startswith(b'AT,ERR'):
                cmd_in.put(msg)

            # handle possible errors
            elif msg.startswith(b'AT,ERR') or msg.startswith(b'ERR'):
                self.handle_errors(msg)

            # log everything else
            else:
                self.display_protocol('log-in', f'Ignored message: {msg}')

    def do_setup(self):
        setup_cmd_list = list()

        # Test cmd
        setup_cmd_list.append(CmdAndAnswers(b'AT', AT_OK))
        # Reset module
        setup_cmd_list.append(CmdAndAnswers(b'AT+RST', (AT_OK, b'Vendor:Himalaya')))
        # Set config string
        setup_cmd_list.append(CmdAndAnswers(b'AT+CFG=433000000,20,9,10,4,1,0,0,0,0,3000,8,10',
                                            AT_OK))  # AT+CFG=433000000,5,9,7,4,1,0,0,0,0,3000,8,10
        # Set address
        setup_cmd_list.append(CmdAndAnswers(b'AT+ADDR=' + self.address, AT_OK))
        # Set Destination
        setup_cmd_list.append(CmdAndAnswers(b'AT+DEST=FFFF', AT_OK))
        # Activate modules receive mode
        setup_cmd_list.append(CmdAndAnswers(b'AT+RX', AT_OK, lambda x: self.display_protocol('info', 'Setup Done.')))

        self.to_out_queue(setup_cmd_list)


def reset_module():
    print("resetting lora module...")
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(18, GPIO.OUT)
    GPIO.output(18, GPIO.HIGH)
    time.sleep(1)
    GPIO.output(18, GPIO.LOW)
    GPIO.cleanup()


def input_address():
    input_addr = None

    while input_addr is None:
        input_addr = input('Address: ')
        if len(input_addr) != 4 \
                or int(input_addr) not in range(1, 21) \
                or not input_addr.isascii():
            print('Wrong address format.')
            input_addr = None

    return input_addr.encode('ascii')


def input_logging_bool(kind: str) -> bool:
    input_deb = None

    while input_deb is None:
        input_deb = input(f'Print {kind} messages to "Logs and Errors" (y/n): ')
        input_deb = input_deb.lower()
        if input_deb not in ['y', 'n']:
            print('Please only enter "y" for yes or "n" for no')
            input_deb = None

    return input_deb == 'y'


if __name__ == '__main__':

    in_address = input_address()
    in_show_debug = input_logging_bool('debug')
    in_show_logging = input_logging_bool('logging')
    in_show_info = input_logging_bool('info')

    # setup uart
    ser = serial.Serial(
        port='/dev/ttyS0',
        baudrate=115200,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS
    )
    # make sure uart is open
    if not ser.is_open:
        ser.open()

    lora_controller = LoRaController(
        address=in_address,
        show_debug=in_show_debug,
        show_log=in_show_logging,
        show_info=in_show_info
    )

    # create protocol-machine
    protocol = Protocol(
        address=in_address.decode('ascii'),
        msg_in=msg_in,
        msg_out=lora_controller.send_message,
        to_display=lora_controller.display_protocol
    )

    # create GUI
    win = LoRaUI(
        on_send=lora_controller.send_via_protocol,
        on_cmd=lora_controller.handle_user_commands,
        title=f'AODV_Light for Node {in_address.decode("ascii")}')

    # schedule setup in cmd_out queue
    lora_controller.do_setup()

    # start loop threads
    try:
        _thread.start_new_thread(protocol.protocol_loop, ())
        try:
            _thread.start_new_thread(lora_controller.read_uart_to_protocol_loop, ())
            _thread.start_new_thread(lora_controller.write_msg_out_loop, ())
        except LoRaError as e:
            print(e)
            cmd_in.put(b'break')
            cmd_in = queue.Queue
            cmd_out.put(b'break')
            cmd_out = queue.Queue

            reset_module()
    except (KeyboardInterrupt, SystemExit, serial.SerialException) as e:
        print(e)
        cmd_in.put(b'break')
        cmd_out.put(b'break')
        msg_in.put(b'break')
        sys.exit()

    # catch main thread in GUI-Loop, so program ends when window closes
    win.mainloop()

    # close uart
    ser.close()
