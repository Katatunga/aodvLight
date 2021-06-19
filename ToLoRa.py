from __future__ import annotations

import threading
import time
from typing import Union

import serial
import _thread
import queue

from LoRaUI import LoRaUI
# from Protocol import Protocol

# often used strings

AT_OK = b'AT,OK'
LINEBREAK = b'\r\n'
ADDRESS = b'0004'

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
# TODO: Only for testing; needs to use protocol
def send_message(msg: bytes, address: bytes):
    def print_msg_sent(answer):
        if answer == 'AT,SENDED':
            win.write_to_messages(str(msg), str(address), True)
    send_cmds = list()
    send_cmds.append(CmdAndAnswers(b'AT+DEST=' + address, AT_OK))
    send_cmds.append(CmdAndAnswers(b'AT+SEND=' + bytes(len(msg)), AT_OK))
    send_cmds.append(CmdAndAnswers(msg, (b'AT,SENDING', b'AT,SENDED'), print_msg_sent))
    to_out_queue(send_cmds)


# write (multiple) commands to cmd_out queue (synchronized)
def to_out_queue(cmds_and_answers: list[CmdAndAnswers]):
    # synchronize (for sequential puts)
    with lock:
        for elem in cmds_and_answers:
            # put command and expected answer(s) into queue
            cmd_out.put(elem)


def write_msg_out_loop():
    """ write the commands in cmd_out queue to uart and wait for and handle the answers in cmd_in """
    while 1:
        # get next command and expected answer(s) (as instance of CmdAndAnswers)
        cmd_and_answers = cmd_out.get(True)

        # make sure cmd_and_answers is of type CmdAndAnswers
        if not isinstance(cmd_and_answers, CmdAndAnswers):
            raise TypeError('Did not use correct class to represent command')

        # write command to uart
        ser.write(cmd_and_answers.cmd)

        # log outgoing commands
        win.write_to_logs(str(cmd_and_answers.cmd.rstrip(LINEBREAK)), True)

        # for each expected answer
        for elem in cmd_and_answers.answers:
            try:
                # get the actual answer (and strip off LINEBREAK)
                answer = cmd_in.get(True, timeout=wait_secs_for_uart_answer)
                answer = bytes(answer).rstrip(LINEBREAK)

                # log answer
                win.write_to_logs(str(answer))

                # if actual answer is not the expected answer (should not happen), raise error
                if elem is not None and answer != elem:
                    raise ValueError('"' + str(cmd_and_answers.cmd) + '" was not answered with "' +
                                     str(elem) + '", but instead with "' + str(answer) + '"')

                # if cmd_and_answers contains a callback, call it with the actual answer
                if cmd_and_answers.callback:
                    cmd_and_answers.callback(answer)

            except queue.Empty:
                handle_errors('Got no answer to command "' + str(cmd_and_answers.cmd.rstrip(LINEBREAK)) + '"')

        # wait a little to avoid CPU_busy error TODO: TEST: may not be needed since we waited for answer
        time.sleep(wait_secs_to_next_cmd)


# Option 1 (no extra-thread)
def handle_incoming_msg(msg):
    # translate incoming message string to object
    msg = IncomingMessage(msg)
    # write incoming messages to respective output
    win.write_to_messages(msg.content, msg.sender)


def handle_errors(err_msg):
    win.write_error(err_msg)


def read_uart_to_protocol_loop():
    while 1:
        # start with an empty string to put the message in
        msg = b''
        # block until there is something received
        msg += ser.read()
        # block to read until LINEBREAK
        while not msg.endswith(LINEBREAK):
            msg += ser.read()

        # remove LINEBREAK
        msg = msg.rstrip(LINEBREAK)

        # handle actual messages from outside
        if msg.startswith(b'LR'):
            # handle_incoming_msg(msg)
            msg_in.put(msg)
        # handle answers to commands (put them in a queue)
        elif msg.startswith(b'AT'):
            cmd_in.put(msg)
        # handle possible errors
        elif msg.startswith(b'ERR'):
            handle_errors(msg)
        # log everything else
        else:
            win.write_to_logs('Ignored message: ' + msg.decode('ascii'))


def do_setup():
    setup_cmd_list = list()

    def print_setup_done(_):
        win.write_info('Setup Done')

    # Test cmd
    setup_cmd_list.append(CmdAndAnswers(b'AT', AT_OK))
    # Reset module
    setup_cmd_list.append(CmdAndAnswers(b'AT+RST', AT_OK))
    # Set config string
    setup_cmd_list.append(CmdAndAnswers(b'AT+CFG=433000000,20,9,12,4,1,0,0,0,0,3000,8,4', AT_OK))  # AT+CFG=433000000,5,9,6,4,1,0,0,0,0,3000,8,4
    # Set address
    setup_cmd_list.append(CmdAndAnswers(b'AT+ADDR=0004', AT_OK))
    # Activate modules receive mode
    setup_cmd_list.append(CmdAndAnswers(b'AT+RX', AT_OK))
    # Set Destination
    setup_cmd_list.append(CmdAndAnswers(b'AT+DEST=FFFF', AT_OK, print_setup_done))

    to_out_queue(setup_cmd_list)


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

win = LoRaUI(send_message, None, "Testing Tkinter UI")
#protocol = Protocol(ADDRESS)

# lock to use for synchronized sequential job-queueing
lock = threading.RLock()

# schedule setup in cmd_out queue
do_setup()

# start worker threads TODO: use lock as argument?
_thread.start_new_thread(read_uart_to_protocol_loop, ())
_thread.start_new_thread(write_msg_out_loop, ())

win.mainloop()

#print("resetting lora modul...")
#import RPi.GPIO as GPIO
#GPIO.setmode(GPIO.BCM)
#GPIO.setup(18, GPIO.OUT)
#GPIO.output(18, GPIO.HIGH)
#sleep(1)
#GPIO.output(18, GPIO.LOW)
#GPIO.cleanup()
