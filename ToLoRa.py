from __future__ import annotations

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
ADDRESS = b'0004'

# log debug
DEBUG = True
# block for x seconds to wait for the answer to a command
wait_secs_for_uart_answer = 5
# sleep for x seconds to send next command
wait_secs_to_next_cmd = 0.5
# send hello every x seconds
hello_secs = 10

cmd_out = queue.Queue()
cmd_in = queue.Queue()
msg_in = queue.Queue()


class CmdAndAnswers:
    def __init__(self, cmd: bytes, answers: Union[tuple[bytes, ...], bytes], callback=None):
        # make sure cmd ends with LINEBREAK
        self.cmd = cmd if cmd.endswith(LINEBREAK) else cmd + LINEBREAK
        # make sure answers is iterable
        self.answers = answers if isinstance(answers, tuple) else (answers,)

        self.callback = callback


class IncomingMessage:
    def __init__(self, msg_str: bytes):
        # destructuring - will raise ValueError(not enough values to unpack...) if too few arguments
        (lr, self.sender, content_length, self.content) = msg_str.split(b',', 3)

        if not lr == b'LR':
            raise ValueError('Incoming message did not start with "LR"')

        if not int(content_length, 16) == len(self.content):
            raise ValueError('Incoming message is incomplete')


# write to cmd_out queue to send a message (AT+SEND)
def send_message(msg: bytes, address: Union[bytes, str]):
    # if address was passed as a string, encode it as ascii
    if isinstance(address, str):
        if address.isascii():
            address = address.encode('ascii')
        else:
            display_protocol('error', f'Address {address}) was not ASCII-encoded, discarded.')
            return

    # define callback for when the message was sent TODO: may be impractical
    def print_msg_sent(answer):
        if answer == 'AT,SENDED':
            display_protocol('msg-out', str(msg), str(address))

    # queue commands in order, so that there is no interruption by other threads
    send_cmds = list()
    send_cmds.append(CmdAndAnswers(b'AT+DEST=' + address, AT_OK))
    send_cmds.append(CmdAndAnswers(b'AT+SEND=' + str(len(msg)).encode('ascii'), AT_OK))
    send_cmds.append(CmdAndAnswers(msg, (b'AT,SENDING', b'AT,SENDED'), print_msg_sent))
    to_out_queue(send_cmds)


def to_out_queue(cmds_and_answers: list[CmdAndAnswers]):
    """
    Writes (multiple) commands to cmd_out queue (synchronized)
    :param cmds_and_answers: commands to write to uart and answers to expect
    :type cmds_and_answers: CmdAndAnswers
    """
    # synchronize (for sequential puts)
    with lock:
        for elem in cmds_and_answers:
            # put command and expected answer(s) into queue
            cmd_out.put(elem)


def write_msg_out_loop():
    """ write the commands in cmd_out queue to uart, then wait for and handle the answers in cmd_in """
    while 1:
        # get next command and expected answer(s) (as instance of CmdAndAnswers)
        cmd_and_answers = cmd_out.get(True)

        # make sure cmd_and_answers is of type CmdAndAnswers
        if not isinstance(cmd_and_answers, CmdAndAnswers):
            raise TypeError('Did not use correct class to represent command')

        # write command to uart
        ser.write(cmd_and_answers.cmd)

        # debug log outgoing commands
        display_protocol('debug-out', str(cmd_and_answers.cmd.rstrip(LINEBREAK)))

        # for each expected answer
        for elem in cmd_and_answers.answers:
            try:
                # get the actual answer (and strip off LINEBREAK)
                answer = cmd_in.get(True, timeout=wait_secs_for_uart_answer)
                answer = bytes(answer).rstrip(LINEBREAK)

                # debug log answer
                display_protocol('debug-in', str(answer))

                # if actual answer is not the expected answer (should not happen), raise error
                if elem is not None and answer != elem:
                    handle_errors(b'"' + cmd_and_answers.cmd + b'" was not answered with "' +
                                  elem + b'", but instead with "' + answer + b'"')

                # if cmd_and_answers contains a callback, call it with the actual answer
                if cmd_and_answers.callback:
                    cmd_and_answers.callback(answer)

            except queue.Empty:
                handle_errors(b'Got no answer to command "' + bytes(cmd_and_answers.cmd.rstrip(LINEBREAK)) + b'"')

        # wait a little to avoid CPU_busy error TODO: TEST: may not be needed since we waited for answer
        time.sleep(wait_secs_to_next_cmd)


def display_protocol(cmd: str, msg: Union[str, int, bytes], address: Optional[str] = None, state: Optional[str] = None) \
        -> Optional[int]:
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
            win.write_to_logs(msg)
        elif cmd == 'log-out':
            win.write_to_logs(msg, True)

        elif cmd == 'debug-in':
            if DEBUG:
                win.write_to_logs(msg)
        elif cmd == 'debug-out':
            if DEBUG:
                win.write_to_logs(msg, True)

        elif cmd == 'info':
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


def send_via_protocol(msg: str, address: str):
    display_id = display_protocol('msg-out', msg, address)

    if address == 'FFFF':
        display_protocol('msg-state', display_id, address=address, state='ERROR: address "FFFF" invalid')
        display_protocol('error', f'User tried to send Message ({msg}) to address "FFFF", discarded.')
        return
    elif not msg.isascii():
        display_protocol('msg-state', display_id, address=address, state='ERROR: Non-ascii')
        display_protocol('error', f'Message ({msg}) was not ASCII-encoded, discarded.')
        return
    else:
        protocol.send_s_t_r(
            dest_addr=address,
            payload=msg.encode('ascii'),
            display_id=display_id
        )


def handle_user_commands(cmd: str, address: str):
    if cmd == 'table':
        table = ''
        for y in protocol.routes.keys():
            table += f'{y}: {protocol.routes.get(y)}\n'
        print(table)


def handle_errors(err_msg: bytes):
    if err_msg == b'ERR: CPU_BUSY':
        display_protocol('error', f'Got: "{err_msg.decode("ascii")}". Reset module.')
        reset_module()
    else:
        display_protocol('error', err_msg.decode('ascii'))


def reset_module():
    print("resetting lora module...")
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(18, GPIO.OUT)
    GPIO.output(18, GPIO.HIGH)
    time.sleep(1)
    GPIO.output(18, GPIO.LOW)
    GPIO.cleanup()


def read_uart_to_protocol_loop():
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

        # handle answers to commands (put them in a queue)
        elif msg.startswith(b'AT') and not msg.startswith(b'AT,ERR'):
            cmd_in.put(msg)

        # handle possible errors
        elif msg.startswith(b'AT,ERR') or msg.startswith(b'ERR'):
            handle_errors(msg)

        # log everything else
        else:
            display_protocol('log-in', f'Ignored message: {msg}')


def do_setup():
    setup_cmd_list = list()

    # Test cmd
    setup_cmd_list.append(CmdAndAnswers(b'AT', AT_OK))
    # Reset module
    setup_cmd_list.append(CmdAndAnswers(b'AT+RST', AT_OK))
    # Set config string
    setup_cmd_list.append(CmdAndAnswers(b'AT+CFG=433000000,20,9,12,4,1,0,0,0,0,3000,8,4',
                                        AT_OK))  # AT+CFG=433000000,5,9,7,4,1,0,0,0,0,3000,8,10
    # Set address
    setup_cmd_list.append(CmdAndAnswers(b'AT+ADDR=' + ADDRESS, AT_OK))
    # Set Destination
    setup_cmd_list.append(CmdAndAnswers(b'AT+DEST=FFFF', AT_OK))
    # Activate modules receive mode
    setup_cmd_list.append(CmdAndAnswers(b'AT+RX', AT_OK, lambda x: display_protocol('info', 'Setup Done.')))

    to_out_queue(setup_cmd_list)


def input_address():
    input_addr = None

    while input_addr is None:
        input_addr = input('Address: ')
        if len(input_addr) != 4 \
                or int(input_addr) not in range(1, 21)\
                or not input_addr.isascii():
            print('Wrong address format.')
            input_addr = None

    return input_addr.encode('ascii')


def input_debug():
    input_deb = None

    while input_deb is None:
        input_deb = input('Print debug messages to "Logs and Errors" (y/n): ')
        input_deb = input_deb.lower()
        if input_deb not in ['y', 'n']:
            print('Please only enter "y" for yes or "n" for no')
            input_deb = None

    return input_deb == 'y'


if __name__ == '__main__':

    ADDRESS = input_address()
    DEBUG = input_debug()

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

    # create protocol-machine
    protocol = Protocol(
        address=ADDRESS.decode('ascii'),
        msg_in=msg_in,
        msg_out=send_message,
        to_display=display_protocol
    )

    # create GUI
    win = LoRaUI(send_via_protocol, handle_user_commands, f'AODV_Light for Node {ADDRESS.decode("ascii")}')

    # lock to use for synchronized sequential job-queueing
    lock = threading.RLock()

    # schedule setup in cmd_out queue
    do_setup()

    # start loop threads TODO: use lock as argument?
    _thread.start_new_thread(read_uart_to_protocol_loop, ())
    _thread.start_new_thread(write_msg_out_loop, ())
    _thread.start_new_thread(protocol.protocol_loop, ())

    # catch main thread in GUI-Loop, so program ends when window closes
    win.mainloop()

    # close uart
    ser.close()
