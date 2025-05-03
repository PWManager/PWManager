import tkinter as tk
from tkinter import messagebox
import os
import json
import random as rand
from cryptography.fernet import Fernet
import pyotp as TwoFactorAuth
import pyperclip
import string
import base64

KEY_FILE = "key.key"
TWOFACTORFILE = "2fa.json"
PASSWORDS_FILE = "passwords.json"

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

# Проверка существования JSON файла
if not os.path.exists(PASSWORDS_FILE):
    with open(PASSWORDS_FILE, "w") as f:
        json.dump({}, f)
        
if not os.path.exists(TWOFACTORFILE):
    with open(TWOFACTORFILE, "w") as f:
        json.dump({}, f)
        
class GuiFunctions:
    def truncate_text(self, text, length):
        return text if len(text) <= length else text[:length - 3] + "..."

class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PWManager")
        self.geometry("500x660")
        self.iconbitmap("icon.ico")  # Make sure the icon.ico file exists in the same directory
        self.resizable(False, False)
        self.config(bg="#1f1f1f")
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        
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
        
        self.twofa_create_button = tk.Button(self, text="Создать 2FA пароль", bg="#2196f3", fg="white", font=("Arial", 16),
                                             command=self.twofa_create)
        
        self.twofa_create_button.pack(pady=10)
        
        self.towfa_auth_button = tk.Button(self, text="Просмотр 2FA паролей", bg="#2196f3", fg="white", font=("Arial", 16),
                                           command=self.towfa_auth)
        
        self.towfa_auth_button.pack(pady=10)
        
        self.search_button = tk.Button(self, text="Поиск", bg="#2196f3", fg="white", font=("Arial", 16),
                                       command=self.search_gui)
        
        self.search_button.pack(pady=10)
        
        self.bind("<Shift-F3>", self.crash)
        self.bind("<Shift-F2>", self.on_program_exit_event)
        self.bind("<F11>", self.toogle_fullscreen)
        
    def on_exit(self):
        self.destroy()
        
    def toogle_fullscreen(self, event):
        self.attributes("-fullscreen", not self.attributes("-fullscreen"))
        
    def search(self, query):
        with open(PASSWORDS_FILE, "r") as f:
            passwords = json.load(f)

        matching_passwords = []
        for site, password in passwords.items():
            if query.lower() in site.lower():
                passw = cipher.decrypt(password.replace("PWManager-Encrypted-Password-v1.0:", "")).decode()
                matching_passwords.append((site, GuiFunctions.truncate_text(passw, 10), ))

        return matching_passwords if matching_passwords else ["Error", f"Cannot find password by query: {query}"]
    
    def search_gui(self):
        win = tk.Toplevel(self)
        win.title("Поиск паролей")
        win.iconbitmap("icon.ico")
        win.geometry("500x650")
        win.config(bg="#1f1f1f")
        
        def on_search_query_enter(event):
            query = search_query.get()
            results = self.search(query)
            
            if isinstance(results[0], str) and results[0] == "Error":
                results_str = results[1]  # просто текст ошибки
            else:
                results_str = "\n".join([f"{site}: {password}" for site, password in results])
            
            results_label.config(text=results_str)
        
        search_query = tk.Entry(win)
        search_query.pack(padx=10, pady=10)
        search_query.focus_set()
        
        search_button = tk.Button(win, text="Поиск", bg="#2196f3", fg="white", font=("Arial", 16),
                                  command=lambda: on_search_query_enter(None))
        
        search_button.pack(padx=10, pady=10)
        
        results_label = tk.Label(win, text="", bg="#1f1f1f", fg="white", font=("Arial", 16))
        results_label.pack(padx=10, pady=10)

        search_query.bind("<Return>", on_search_query_enter)
        
    def on_program_exit_event(self, event, code: str | None = "Closed by user"):
        for widget in self.winfo_children():
            widget.destroy()
        else:
            label = tk.Label(self, text="Теперь можно закрыть PWManager через кнопку.", bg="#1f1f1f", fg="white", font=("Arial", 16))
            label.pack(expand=True)
            
            label2 = tk.Label(self, text=f"Код закрытия: {base64.b64encode(code.encode()).decode()}", bg="#1f1f1f", fg="white", font=("Arial", 16))
            label2.pack(expand=True)
        
    def twofa_create(self):
        from tkinter.simpledialog import askstring
        site = askstring("Сайт", "Введите название сайта (например, 'google.com'):")
        secret = askstring("Секретный ключ", "Введите секретный ключ (например, 'ABCDEF1234567890'):")

        if not site or not secret:
            messagebox.showerror("Ошибка", "Оба поля обязательны!")
            return

        encrypted_secret = "PWManager-Encrypted-2FA-v1.0:" + cipher.encrypt(secret.encode()).decode()

        if os.path.exists(TWOFACTORFILE):
            with open(TWOFACTORFILE, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
        else:
            data = {}

        data[site] = encrypted_secret

        with open(TWOFACTORFILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Успех", "2FA ключ успешно сохранён!")
        
    def towfa_auth(self):
        try:
            with open(TWOFACTORFILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

        if not data:
            messagebox.showinfo("Нет паролей", "2FA ключи не найдены. Сначала добавьте хотя бы один.")
            return

        window = tk.Toplevel(self)
        window.iconbitmap("icon.ico")
        window.title("2FA (PWManager)")
        window.geometry("500x500")
        window.configure(bg="#1f1f1f")

        canvas = tk.Canvas(window, bg="#1f1f1f")
        scrollbar = tk.Scrollbar(window, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg="#1f1f1f")

        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        site_widgets = {}

        def decrypt_2fa_secret(encrypted: str) -> str:
            if encrypted.startswith("PWManager-Encrypted-2FA-v1.0:"):
                encrypted = encrypted.replace("PWManager-Encrypted-2FA-v1.0:", "")
            return cipher.decrypt(encrypted.encode()).decode()

        def update_codes():
            for site, encrypted_secret in data.items():
                try:
                    secret = decrypt_2fa_secret(encrypted_secret)
                    topt = TwoFactorAuth.TOTP(secret)
                    code = topt.now()
                    label, button = site_widgets[site]
                    label.config(text=f"{site}: {code}")
                    button.config(command=lambda c=code: pyperclip.copy(c))
                except Exception as e:
                    label, button = site_widgets[site]
                    label.config(text=f"{site}: Ошибка")
            window.after(1000, update_codes)

        for site, encrypted_secret in data.items():
            try:
                secret = decrypt_2fa_secret(encrypted_secret)
                topt = TwoFactorAuth.TOTP(secret)
                code = topt.now()
            except Exception as e:
                code = "Ошибка"

            frame = tk.Frame(scroll_frame, bg="#1f1f1f")
            frame.pack(fill=tk.X, pady=5, padx=10)

            label = tk.Label(frame, text=f"{site}: {code}", fg="white", bg="#1f1f1f", font=("Arial", 12))
            label.pack(side=tk.LEFT)

            button = tk.Button(frame, text="Копировать", command=lambda c=code: pyperclip.copy(c),
                            bg="#2196f3", fg="white", font=("Arial", 10))
            button.pack(side=tk.RIGHT)
            
            def delete_site(site_name=site, frame_to_destroy=frame):
                if messagebox.askyesno("Удаление", f"Удалить 2FA ключ для '{site_name}'?"):
                    del data[site_name]
                    with open(TWOFACTORFILE, "w") as f:
                        json.dump(data, f, indent=4)
                    frame_to_destroy.destroy()
                    del site_widgets[site_name]
                    messagebox.showinfo("Успех", f"2FA ключ для '{site_name}' удалён.")
            
            button_delete = tk.Button(frame, text="Удалить", command=delete_site,
                                    bg="#f44336", fg="white", font=("Arial", 10))
            button_delete.pack(side=tk.RIGHT, padx=5)

            site_widgets[site] = (label, button)

        scroll_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

        def on_mouse_scroll(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")

        canvas.bind_all("<MouseWheel>", on_mouse_scroll)

        update_codes()
                            
    def generate_password(self):
        from tkinter.simpledialog import askinteger
        possible = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        range_of = askinteger("Диапазон", "Введите количество символов (например, 10):")
        password = "".join(rand.choice(possible) for _ in range(range_of))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
    def crash(self, event):
        self.destroy()
        
    def show_about(self):
        messagebox.showinfo("О программе", "© PWManager team. MIT License.")
        
    def save_password(self, site, password):
        if not site or not password:
            messagebox.showerror("Ошибка", "Поля сайта и пароля не могут быть пустыми!")
            return
        
        with open(PASSWORDS_FILE, "r") as f:
            data = json.load(f)
        
        if site in data:
            messagebox.showerror("Ошибка", "Пароль для этого сайта уже существует!")
            return
        
        encrypted_password = "PWManager-Encrypted-Password-v1.0:" + cipher.encrypt(password.encode()).decode()
        data[site] = encrypted_password

        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Успех", "Пароль успешно сохранен!")

    def delete_password(self, site):
        with open(PASSWORDS_FILE, "r") as f:
            data = json.load(f)
        
        if site not in data:
            messagebox.showerror("Ошибка", "Пароль для этого сайта не найден!")
            return
        
        if messagebox.askyesno("Удаление пароля", "Вы уверены, что хотите удалить этот пароль?"):
            pass
        else:
            messagebox.showinfo("Отмена", "Удаление пароля отменено.")
            return
        
        del data[site]
        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Успех", "Пароль успешно удален!")

    def save_gui_password(self):
        site = self.site_entry.get()
        password = self.password_entry.get()
        self.save_password(site, password)

    def delete_gui_password(self):
        site = self.site_entry.get()
        self.delete_password(site)

    def copy_to_clipboard(self, site):
        with open(PASSWORDS_FILE, "r") as f:
            data = json.load(f)
        
        if site not in data:
            messagebox.showerror("Ошибка", "Пароль для этого сайта не найден!")
            return
        
        password = cipher.decrypt(data[site].replace("PWManager-Encrypted-Password-v1.0:", "").replace("PWManager-Encrypted-2FA-v1.0", "").encode()).decode()
        pyperclip.copy(password)
        messagebox.showinfo("Успех", "Пароль скопирован в буфер обмена!")


    def view_passwords(self):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            data = {"Ошибка": cipher.encrypt("Ошибка декодирования файла паролей.".encode()).decode()}

        if not data:
            messagebox.showinfo("Нет паролей", "Пароли еще не сохранены. Сначала сохраните пароль для любого сайта.")
            return

        # Создание нового окна для просмотра паролей
        view_window = tk.Toplevel(self)
        view_window.iconbitmap("icon.ico")
        view_window.title("Просмотр паролей (PWManager)")
        view_window.geometry("500x500")
        view_window.configure(bg="#1f1f1f")

        # Создание холста с полосой прокрутки
        canvas = tk.Canvas(view_window, bg="#1f1f1f")
        scrollbar = tk.Scrollbar(view_window, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar_x = tk.Scrollbar(view_window, orient=tk.HORIZONTAL, command=canvas.xview)
        scroll_frame = tk.Frame(canvas, bg="#1f1f1f")

        # Настройка полосы прокрутки
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.configure(xscrollcommand=scrollbar_x.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        # Заполнение паролями
        for site, encrypted_password in data.items():
            password = cipher.decrypt(encrypted_password.replace("PWManager-Encrypted-Password-v1.0:", ""))
            
            site_label = tk.Label(scroll_frame, text=f"{site}: ", bg="#1f1f1f", fg="white", font=("Arial", 12))
            site_label.pack(side=tk.LEFT)
            
            frame = tk.Frame(scroll_frame, bg="#1f1f1f")
            frame.pack(fill=tk.X, pady=5, padx=10)

            password_var = tk.StringVar(value="*" * len(password))
            is_visible = [False]  # Обходим ограничение замыканий в Python

            password_label = tk.Label(frame, textvariable=password_var, bg="#1f1f1f", fg="white", font=("Arial", 12))
            password_label.pack(side=tk.LEFT, padx=(0, 5))

            def toggle_password(p=password, var=password_var, flag=is_visible):
                flag[0] = not flag[0]
                var.set(p if flag[0] else "*" * len(p))

            toggle_button = tk.Button(frame, text="N", bg="#2196f3", fg="white", font=("Webdings", 10),
                                    command=toggle_password)
            toggle_button.pack(side=tk.RIGHT, padx=5)

            copy_button = tk.Button(frame, text="Копировать", bg="#4caf50", fg="white", font=("Arial", 10),
                                    command=lambda site=site: self.copy_to_clipboard(site))
            copy_button.pack(side=tk.RIGHT, padx=5)
            
            delete_button = tk.Button(frame, text="Удалить", bg="#f44336", fg="white", font=("Arial", 10),
                                      command=lambda site=site: self.delete_password(site))
            
            delete_button.pack(side=tk.RIGHT, padx=5)


        # Обновление прокручиваемой области
        scroll_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

        # Привязка прокрутки мышью для лучшего UX
        def on_mouse_scroll(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")

        canvas.bind_all("<MouseWheel>", on_mouse_scroll)

if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()