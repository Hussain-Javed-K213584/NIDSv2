import tkinter as tk
from tkinter import ttk

class ScrollableMessageBox(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        self.canvas = tk.Canvas(self)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

    def add_message(self, message):
        label = tk.Label(self.scrollable_frame, text=message, wraplength=500, justify="left")
        label.pack(anchor="w", padx=10, pady=5)

def main():
    root = tk.Tk()
    root.title("Scrollable Message Box")
    root.geometry("600x400")

    message_box = ScrollableMessageBox(root)
    message_box.pack(fill="both", expand=True)

    # Add some example messages
    messages = [
        "This is a sample message.",
        "Here's another message.",
        "And one more for good measure.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed aliquam augue et risus tempor.",
        "Fusce ut velit pulvinar, rutrum velit ut, volutpat nisi."
    ]

    for message in messages:
        message_box.add_message(message)

    root.mainloop()

if __name__ == "__main__":
    main()
