import tkinter as tk
from MainWindow import MainWindow


if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    app.update_loop()
    root.mainloop()
