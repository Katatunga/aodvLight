import tkinter.constants
import tkinter
from tkinter import *
import tkinter.scrolledtext


SEPERATOR = ('-' * 36)


class LoRaUI:

    # -------------------------------------------------------------
    #                       SETUP
    # -------------------------------------------------------------

    def get_scrolled_text(self, fg):
        scrollable = tkinter.scrolledtext.ScrolledText(self.window, bg='grey', fg=fg)
        scrollable.grid(row=1, column=0, columnspan=3)
        scrollable.tag_configure('tag-center', justify='center')
        scrollable.tag_configure('tag-left', justify='left')
        scrollable.tag_configure('tag-right', justify='right')
        return scrollable

    def __init__(self, on_send: callable, on_cmd: callable, title: str = 'LoRa'):
        self.window = Tk()
        self.window.title(title)
        self.window.configure(background="black")

        Label(
            self.window,
            text="Messages",
            bg="grey",
            fg="black",
            font="none 12 bold",
            justify="center"
        ).grid(row=0, column=0, columnspan=3, sticky='nesw')

        # Scrollable text for messages (in and out)

        self.messages = self.get_scrolled_text('black')
        self.messages.grid(row=1, column=0, columnspan=3)

        # messages.configure(state='disabled')
        # messages.insert(Tkinter.INSERT, "anything")
        # messages.configure(state='normal')
        # messages.insert(Tkinter.INSERT, "anything2")
        # messages.configure(state='disabled')

        # Scrollable text for logs, AT-Commands, Infos, Errors
        # Header for logging text
        Label(
            self.window,
            text="Logs and Errors",
            bg="grey",
            fg="white",
            font="none 12 bold",
            justify="right"
        ).grid(row=0, column=3, columnspan=3, sticky='nesw')

        self.log_text = self.get_scrolled_text('white')
        self.log_text.grid(row=1, column=3, columnspan=3)

        Label(
            self.window,
            text="Send to (ignored in cmds)",
            bg="grey",
            fg="black",
            justify='left'
        ).grid(row=2, column=0, sticky='nesw')

        # List of addresses (0001 - 0020)
        addresses = ['0'*(4-len(str(x))) + str(x) for x in range(1, 21)]
        addresses.insert(0, 'FFFF')

        # Define chat string list
        self.chats = list()
        for a in addresses:
            self.chats.append(list([('Chat with ' + a, 'center')]))

        # Define Dropdown
        self.dd_option = StringVar(self.window)
        self.dd_option.set('FFFF')

        self.dd_option.trace('w', self.update_messages)

        dd_menu = OptionMenu(self.window, self.dd_option, *addresses)
        dd_menu.grid(row=2, column=0, sticky='nes')

        # Define textentry
        text_entry = Entry(self.window, bg='white', fg='black')
        text_entry.bind('<Return>', lambda _: callback_if_textentry(on_send))
        text_entry.bind('<Control-Return>', lambda _: callback_if_textentry(on_cmd))
        text_entry.bind('<Control-BackSpace>', lambda _: text_entry.delete(0, tkinter.END))
        text_entry.grid(row=2, column=1, columnspan=4, sticky='nesw')

        # ------------------------------
        #     Callback for Buttons
        # ------------------------------

        def callback_if_textentry(callback):
            s = text_entry.get()
            if s != '':
                callback(s, self.dd_option.get())

        Button(self.window, text='SEND', command=lambda: callback_if_textentry(on_send)) \
            .grid(row=2, column=4, sticky='nesw')
        Button(self.window, text='COMMAND', command=lambda: callback_if_textentry(on_cmd)) \
            .grid(row=2, column=5, sticky='nesw')

        self.update_messages()

    def mainloop(self):
        self.window.mainloop()

    # -------------------------------------------------------------
    #                     Functionality
    # -------------------------------------------------------------


    def update_messages(self, *args):
        """
        Updates text in "messages' according to the currently chosen option in self.dd_option
        :param args: ignored
        """
        self.messages.configure(state='normal')
        self.messages.delete(1.0, END)
        index = 0 if self.dd_option.get() == 'FFFF' else int(self.dd_option.get())
        for i in self.chats[index]:
            self.messages.insert(tkinter.constants.INSERT, i[0], 'tag-' + i[1])

        self.messages.configure(state='disabled')
        self.messages.yview_moveto(1)

    def write_to_messages(self, msg: str, address: str, is_out: bool = False) -> int:
        """
        Writes message to chat of 'address', aligned left if 'is_out' is True, otherwise aligned right.
        Then calls self.update_messages() to update the currently displayed text.\n
        :return: The index of this message as an int. This can be used to reference the message in the future.\n
        """
        sender_str = 'From ' + address + ':' if not is_out else 'I wrote:'

        int_address = 0 if address == 'FFFF' else int(address)

        align = 'right' if not is_out else 'left'

        s = '\n' + SEPERATOR + '\n' + \
            sender_str + '\n' + \
            msg + \
            '\n' + SEPERATOR + '\n'

        index = len(self.chats[int_address])
        self.chats[int_address].append((s, align))
        # there are no in_msgs from FFFF, but that chat should be used to display all incoming messages
        if not is_out:
            self.chats[0].append((s, align))
        self.update_messages()
        return index

    def update_message_state(self, address: str, index: int, state: str):
        """
        Updates the messages state to 'state'. The state is used for the user to better understand
        what happened to their message. If state is too long to display, 'Unknown State' is used as 'state'.\n
        :param address: address of the communication partner
        :type address: str
        :param index: index of the message to update (received from self.write_to_messages() on message creation)
        :type index: int
        :param state: The state to update the message with. Can be any str with len() lesser than 34
        :type state: str
        """
        # generate new first line
        header_line = self.construct_header_line(state)
        # get correct chat
        int_address = int(address) if address != 'FFFF' else 0
        chat = self.chats[int_address]
        # extract message from chat
        msg = chat[index][0]
        # get position of second '\n'
        end_of_first_line = msg.index('\n', 1)
        # replace first line with new first line
        chat[index] = (header_line + msg[end_of_first_line:], chat[index][1])
        self.update_messages()

    def construct_header_line(self, header) -> str:
        if len(header) > (len(SEPERATOR) - 2):
            header = 'Header too long'
        # calculate amount of '-' left of state
        half_length_floored = int((len(SEPERATOR) - len(header)) / 2)
        # generate new first line
        return f'\n{("-" * half_length_floored)}{header}{("-" * (len(SEPERATOR) - len(header) - half_length_floored))}'

    def write_to_logs(self, log: str, is_out: bool = False, header: str = ''):
        align = 'tag-'
        align += 'left' if is_out else 'right'

        s = f'{self.construct_header_line(header)}\n{log}\n{SEPERATOR}\n'
        self.log_text.insert('end', s, align)
        self.log_text.yview_moveto(1)

    def write_error(self, error: str):
        self.__write_middle(error, 'ERROR')

    def write_info(self, info: str):
        self.__write_middle(info, 'INFO')

    def __write_middle(self, content: str, header: str = ''):
        s = f'{self.construct_header_line(header)}\n{content}\n{SEPERATOR}\n'
        self.log_text.insert('end', s, 'tag-center')
        self.log_text.yview_moveto(1)


def print_send(msg, dest):
    win.write_to_messages(msg, dest, True)
    win.write_to_messages("Hallo", dest, False)


def print_cmd(cmd, dest):
    if cmd == "error":
        win.write_error("Etwas Schlimmes ist passiert")
    else:
        win.write_to_logs(cmd, True)
        win.write_to_logs("AT,OK")


if __name__ == '__main__':
    win = LoRaUI(print_send, print_cmd, 'Testing Tkinter')
    win.mainloop()
