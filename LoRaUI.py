import tkinter.constants
import tkinter
from tkinter import *
import tkinter.scrolledtext


class LoRaUI:

    def get_scrolled_text(self, fg):
        scrollable = tkinter.scrolledtext.ScrolledText(self.window, bg='grey', fg=fg)
        scrollable.grid(row=1, column=0, columnspan=3)
        scrollable.tag_configure('tag-center', justify='center')
        scrollable.tag_configure('tag-left', justify='left')
        scrollable.tag_configure('tag-right', justify='right')
        return scrollable

    def __init__(self, on_send, on_cmd, title='LoRa'):
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
        text_entry.grid(row=2, column=1, columnspan=4, sticky='nesw')

        def callback_if_textentry(callback):
            s = text_entry.get()
            if s != '':
                callback(bytes(s.encode('ascii')), self.dd_option.get())  # TODO? no error message on non ascii

        Button(self.window, text='SEND', command=lambda: callback_if_textentry(on_send)) \
            .grid(row=2, column=4, sticky='nesw')
        Button(self.window, text='COMMAND', command=lambda: callback_if_textentry(on_cmd)) \
            .grid(row=2, column=5, sticky='nesw')

        self.update_messages()

    def mainloop(self):
        self.window.mainloop()

    # Change text in "messages' on change of self.dd_option
    def update_messages(self, *args):
        self.messages.configure(state='normal')
        self.messages.delete(1.0, END)
        index = 0 if self.dd_option.get() == 'FFFF' else int(self.dd_option.get())
        for i in self.chats[index]:
            self.messages.insert(tkinter.constants.INSERT, i[0], 'tag-' + i[1])

        self.messages.configure(state='disabled')
        self.messages.yview_moveto(1)

    def write_to_messages(self, msg: str, address: str, is_out: bool = False):
        sender_str = 'From ' + address + ':' if not is_out else 'I wrote:'

        int_address = 0 if address == 'FFFF' else int(address)

        align = 'right' if not is_out else 'left'

        s = '\n-----------------------------------\n' + \
            sender_str + '\n' + \
            msg + \
            '\n-----------------------------------\n'
        self.chats[int_address].append((s, align))
        # there are no in_msgs from FFFF, but that chat should be used to display all incoming messages
        if not is_out:
            self.chats[0].append((s, align))
        self.update_messages()

    def write_to_logs(self, log: str, is_out: bool = False):
        cmd_or_ans_str = 'Command:' if is_out else 'Answer:'

        align = 'tag-'
        align += 'left' if is_out else 'right'

        s = '\n-----------------------------------\n' + \
            cmd_or_ans_str + '\n' + \
            log + \
            '\n-----------------------------------\n'
        self.log_text.insert('end', s, align)
        self.log_text.yview_moveto(1)

    def write_error(self, error: str):
        s = '\n---------------ERROR---------------\n' + \
            error + \
            '\n-----------------------------------\n'
        self.log_text.insert('end', s, 'tag-center')
        self.log_text.yview_moveto(1)

    def write_info(self, info: str):
        s = '\n----------------INFO----------------\n' + \
            info + \
            '\n------------------------------------\n'
        self.log_text.insert('end', s, 'tag-center')
        self.log_text.yview_moveto(1)


def print_send(msg, dest):
    win.write_to_messages(msg, dest, True)
    win.write_to_messages("Hallo", dest, False)


def print_cmd(cmd):
    if cmd == "error":
        win.write_error("Etwas Schlimmes ist passiert")
    else:
        win.write_to_logs(cmd, True)
        win.write_to_logs("AT,OK")


if __name__ == '__main__':
    win = LoRaUI(print_send, print_cmd, 'Testing Tkinter')
    win.mainloop()
