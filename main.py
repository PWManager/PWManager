import tkinter as tk
from tkinter import messagebox, scrolledtext
import os
import json
from cryptography.fernet import Fernet
import random as rand
import logging
import win32api

# Генерация ключа, если он не существует
if not os.path.exists("crypt.key"):
    key = Fernet.generate_key()
    try:
        with open("crypt.key", "wb") as key_file:
            key_file.write(key)
    except Exception as e:
        key = Fernet.generate_key().decode()
else:
    key = open("crypt.key", "rb").read()

cipher = Fernet(key)  # Инициализация Fernet с ключом

PASSWORDS_FILE = "passwords.json"

# Проверка существования JSON файла
if not os.path.exists(PASSWORDS_FILE):
    with open(PASSWORDS_FILE, "w") as f:
        json.dump({}, f)
        
with open("PWManager.log", "w") as f:
    f.write("")
        
logging.basicConfig(filename="PWManager.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
PWManager_logger = logging.getLogger("PWManager")

def getWindowsVersion():
    version = win32api.GetVersionEx()

    # Выводим номер версии
    if version[0] == 10:
        return 10
    elif version[0] == 6 and version[1] == 1:
        return 7
    elif version[0] == 6 and version[1] == 2:
        return 8
    elif version[0] == 6 and version[1] == 3:
        return 8.1
    else:
        return version[0]

class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PWManager")
        self.geometry("500x650")
        self.iconbitmap("icon.ico")  # Make sure the icon.ico file exists in the same directory
        self.resizable(False, False)
        self.configure(bg="#1f1f1f")
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        PWManager_logger.debug("Initializing successfully")

        self.site_label = tk.Label(self, text="Сайт:", bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_label.pack(pady=10)

        self.site_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_entry.pack(pady=10)

        self.password_label = tk.Label(self, text="Пароль:", bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_label.pack(pady=10)

        self.password_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_entry.pack(pady=10)

        self.save_button = tk.Button(self, text="Сохранить", bg="#2196f3", fg="white", font=("Arial", 16),
                                   command=self.save_gui_password)
        self.save_button.pack(pady=10)


        self.generate_button = tk.Button(self, text="Сгенерировать пароль", bg="#2196f3", fg="white", font=("Arial", 16),
                                        command=self.generate_password)
        self.generate_button.pack(pady=10)

        self.delete_button = tk.Button(self, text="Удалить", bg="#2196f3", fg="white", font=("Arial", 16),
                                     command=self.delete_gui_password)
        self.delete_button.pack(pady=10)

        self.view_passwords_button = tk.Button(self, text="Просмотр паролей", bg="#2196f3", fg="white", font=("Arial", 16),
                                             command=self.view_passwords)
        self.view_passwords_button.pack(pady=10)
        
        self.bind("<Shift-F3>", self.crash)
        
        PWManager_logger.debug("GUI initialized successfully for elements")
        PWManager_logger.info(f"User's Windows version is {getWindowsVersion()}")
        PWManager_logger.debug("Thread 0 is inited!")
        
    def on_exit(self):
        PWManager_logger.info("GUI closed successfully")
        self.destroy()
                            

    def generate_password(self):
        from tkinter.simpledialog import askinteger
        range_of = askinteger("Диапазон", "Введите количество символов (например, 10):")
        password = "".join(chr(rand.randint(33, 126)) for _ in range(range_of))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        PWManager_logger.debug("Password generated successfully")
        
    def crash(self, event):
        PWManager_logger.error("Unsearchable error!")
        PWManager_logger.critical("GUI crashed by user! (0x0000000000)")

        self.destroy()

    def show_about(self):
        messagebox.showinfo("О программе", "PWManager - Менеджер паролей. Версия 1.0. Автор: @MichaelSoftWare2025 на github.")
        
    def save_password(self, site, password):
        if not site or not password:
            messagebox.showerror("Ошибка", "Поля сайта и пароля не могут быть пустыми!")
            return

        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
                PWManager_logger.debug("JSON file opened successfully. JSON content is: " + str(data))
        except json.JSONDecodeError as e:
            PWManager_logger.error(f"Error decoding passwords file: {e}")
            PWManager_logger.info("Data of passwords file is empty! {}")
            data = {}

        if site in data:
            messagebox.showerror("Ошибка", "Пароль для этого сайта уже существует! Сначала удалите существующий пароль.")
            PWManager_logger.error("Error saving password: Password already exists for this site!")
            return

        encrypted_password = "PWManager-Encrypted-Password-v1.0:" + cipher.encrypt(password.encode()).decode()
        data[site] = encrypted_password

        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Успех", "Пароль успешно сохранен!")
        PWManager_logger.info("Password saved successfully!")

    def delete_password(self, site):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

        if site not in data:
            PWManager_logger.error("Error deleting password: Password not found for this site!")
            messagebox.showerror("Ошибка", "Пароль для этого сайта не найден! Сначала сохраните пароль для этого сайта.")
            return

        del data[site]

        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Успех", "Пароль успешно удален!")
        PWManager_logger.info("Password deleted successfully!")

    def save_gui_password(self):
        site = self.site_entry.get()
        password = self.password_entry.get()
        self.save_password(site, password)

    def delete_gui_password(self):
        site = self.site_entry.get()
        self.delete_password(site)

    def copy_to_clipboard(self, site):
        import pyperclip
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

        if site not in data:
            PWManager_logger.error("Error copying password: Password not found for this site!")
            messagebox.showerror("Ошибка", "Пароль для этого сайта не найден! Сначала сохраните пароль для этого сайта.")
            return

        password = cipher.decrypt(data[site].replace("PWManager-Encrypted-Password-v1.0:", "").encode()).decode()
        pyperclip.copy(password)
        messagebox.showinfo("Успех", "Пароль скопирован в буфер обмена!")
        PWManager_logger.info("Password copied to clipboard successfully!")

    def view_passwords(self):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            PWManager_logger.error(f"Error decoding passwords file: {e}")
            PWManager_logger.info("Data of passwords file is empty! {}")
            data = {"Ошибка": cipher.encrypt("Ошибка декодирования файла паролей.".encode()).decode()}

        if not data:
            PWManager_logger.error("Error viewing passwords: No passwords found!")
            messagebox.showinfo("Нет паролей", "Пароли еще не сохранены. Сначала сохраните пароль для любого сайта.")
            return

        # Создание нового окна для просмотра паролей
        view_window = tk.Toplevel(self)
        view_window.iconbitmap("icon.ico")
        view_window.title("Просмотр паролей (PWManager)")
        PWManager_logger.debug("Password viewer inited!")
        view_window.geometry("500x500")
        view_window.configure(bg="#1f1f1f")

        # Создание холста с полосой прокрутки
        canvas = tk.Canvas(view_window, bg="#1f1f1f")
        scrollbar = tk.Scrollbar(view_window, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg="#1f1f1f")

        # Настройка полосы прокрутки
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        # Заполнение паролями
        for site, encrypted_password in data.items():
            password = cipher.decrypt(encrypted_password.replace("PWManager-Encrypted-Password-v1.0:", "").encode()).decode()

            copy_button = tk.Button(scroll_frame, text=f"{site}: {password}", bg="#1f1f1f", fg="white", font=("Arial", 12),
                                  command=lambda site=site: self.copy_to_clipboard(site))
            copy_button.pack(side=tk.LEFT, padx=5)

        # Обновление прокручиваемой области
        scroll_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

        # Привязка прокрутки мышью для лучшего UX
        def on_mouse_scroll(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")

        canvas.bind_all("<MouseWheel>", on_mouse_scroll)
        PWManager_logger.info("Passwords viewed successfully!")

if __name__ == "__main__":
    app = PasswordManager()
    PWManager_logger.debug("GUI initialized successfully")
    app.mainloop()