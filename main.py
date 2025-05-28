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
import locale
import qrcode
from PIL import Image, ImageTk

def get_system_language():
    # Try the new recommended approach first
    try:
        lang, _ = locale.getlocale()
        if lang:
            return "ru" if lang == "Russian_Russia" else "en"
    except:
        pass

KEY_FILE = "key.key"
TWOFACTORFILE = "2fa.json"
PASSWORDS_FILE = "passwords.json"
LANG_FILE = "lang"

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
    
def change_lang():
    lang = get_system_language()
    
    if lang == "ru":
        return "en"
    else:
        return "ru"
    
def check_lang(russian, english):
    lang = get_system_language()
    
    if lang == "ru":
        return russian
    elif lang == "en":
        return english
    else:
        return english

class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PWManager")
        self.geometry("500x660")
        self.iconbitmap("icon.ico")  # Make sure the icon.ico file exists in the same directory
        self.resizable(False, False)
        self.config(bg="#1f1f1f")
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        
        self.site_label = tk.Label(self, text=check_lang("Сайт:", "Site:"), bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_label.pack(pady=10)

        self.site_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_entry.pack(pady=10)

        self.password_label = tk.Label(self, text=check_lang("Пароль:", "Password:"), bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_label.pack(pady=10)

        self.password_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_entry.pack(pady=10)

        self.save_button = tk.Button(self, text=check_lang("Сохранить пароль", "Save Password"), bg="#2196f3", fg="white", font=("Arial", 16),
                                   command=self.save_gui_password)
        self.save_button.pack(pady=10)


        self.generate_button = tk.Button(self, text=check_lang("Сгенерировать пароль", "Generate Password"), bg="#2196f3", fg="white", font=("Arial", 16),
                                        command=self.generate_password)
        self.generate_button.pack(pady=10)

        self.delete_button = tk.Button(self, text=check_lang("Удалить пароль", "Delete Password"), bg="#2196f3", fg="white", font=("Arial", 16),
                                     command=self.delete_gui_password)
        self.delete_button.pack(pady=10)

        self.view_passwords_button = tk.Button(self, text=check_lang("Просмотр паролей", "View Passwords"), bg="#2196f3", fg="white", font=("Arial", 16),
                                             command=self.view_passwords)
        self.view_passwords_button.pack(pady=10)
        
        self.twofa_create_button = tk.Button(self, text=check_lang("Создать 2FA пароль", "Create 2FA Password"), bg="#2196f3", fg="white", font=("Arial", 16),
                                             command=self.twofa_create)
        
        self.twofa_create_button.pack(pady=10)
        
        self.towfa_auth_button = tk.Button(self, text=check_lang("Просмотр 2FA паролей", "View 2FA Passwords"), bg="#2196f3", fg="white", font=("Arial", 16),
                                           command=self.towfa_auth)
        
        self.towfa_auth_button.pack(pady=10)
        
        self.bind("<Shift-F3>", self.crash)
        self.bind("<Shift-F2>", self.on_program_exit_event)
        self.bind("<F11>", self.toogle_fullscreen)
        
    def on_exit(self):
        self.destroy()
        
    def toogle_fullscreen(self, event):
        self.attributes("-fullscreen", not self.attributes("-fullscreen"))
        
    def on_program_exit_event(self, event, code: str | None = "Closed by user"):
        for widget in self.winfo_children():
            widget.destroy()
        else:
            self.config(bg="blue")
            label = tk.Label(self, text=":(", bg="blue", fg="white", font=("Arial", 100))
            label.pack()
            
            label2 = tk.Label(self, text=check_lang("Теперь можно закрыть PWManager через кнопку.", "You can now close PWManager using the button."), bg="blue", fg="white", font=("Arial", 16))
            label2.pack(expand=True)
            
            label3 = tk.Label(self, text=f"{check_lang('Код закрытия:', 'Exit code:')} {base64.b64encode(code.encode()).decode()}", bg="blue", fg="white", font=("Arial", 16))
            label3.pack(expand=True)
            
            qr = qrcode.QRCode(version=1, box_size=20, border=4)
            qr.add_data(base64.b64encode(code.encode()).decode())
            qr.make(fit=True)
            
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            qr_img = qr_img.resize((300, 300))
            
            qr_img_tk = ImageTk.PhotoImage(qr_img)
            
            label4 = tk.Label(self, image=qr_img_tk, bg="blue", fg="white", font=("Arial", 16))
            
            label4.image = qr_img_tk
            
            label4.pack(expand=True)
            
            button = tk.Button(self, text=check_lang("Закрыть", "Close"), bg="#2196f3", fg="white", font=("Arial", 16),
                               command=self.on_exit)
            
            if self.attributes("-fullscreen"):
                button.pack(expand=True)
        
    def twofa_create(self):
        from tkinter.simpledialog import askstring
        site = askstring(check_lang("Сайт", "Site"), check_lang("Введите название сайта (например, 'google.com'):", "Enter site name (e.g., 'google.com'):"))
        secret = askstring(check_lang("Секретный ключ", "Secret Key"), check_lang("Введите секретный ключ (например, 'ABCDEF1234567890'):", "Enter secret key (e.g., 'ABCDEF1234567890'):"))

        if not site or not secret:
            messagebox.showerror(check_lang("Ошибка", "Error"), check_lang("Оба поля обязательны!", "Both fields are required!"))
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

        messagebox.showinfo(check_lang("Успех", "Success"), check_lang("2FA ключ успешно сохранён!", "2FA key successfully saved!"))
        
    def towfa_auth(self):
        try:
            with open(TWOFACTORFILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

        if not data:
            messagebox.showinfo(check_lang("Нет паролей", "No Passwords"), check_lang("2FA ключи не найдены. Сначала добавьте хотя бы один.", "No 2FA keys found. Add at least one first."))
            return

        window = tk.Toplevel(self)
        window.iconbitmap("icon.ico")
        window.title(check_lang("2FA (PWManager)", "2FA (PWManager)"))
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
                    label.config(text=f"{site}: {check_lang('Ошибка', 'Error')}")
            window.after(1000, update_codes)

        for site, encrypted_secret in data.items():
            try:
                secret = decrypt_2fa_secret(encrypted_secret)
                topt = TwoFactorAuth.TOTP(secret)
                code = topt.now()
            except Exception as e:
                code = check_lang("Ошибка", "Error")

            frame = tk.Frame(scroll_frame, bg="#1f1f1f")
            frame.pack(fill=tk.X, pady=5, padx=10)

            label = tk.Label(frame, text=f"{site}: {code}", fg="white", bg="#1f1f1f", font=("Arial", 12))
            label.pack(side=tk.LEFT)

            button = tk.Button(frame, text=check_lang("Копировать", "Copy"), command=lambda c=code: pyperclip.copy(c),
                            bg="#2196f3", fg="white", font=("Arial", 10))
            button.pack(side=tk.RIGHT)
            
            def delete_site(site_name=site, frame_to_destroy=frame):
                if messagebox.askyesno(check_lang("Удаление", "Delete"), check_lang(f"Удалить 2FA ключ для '{site_name}'?", f"Delete 2FA key for '{site_name}'?")):
                    del data[site_name]
                    with open(TWOFACTORFILE, "w") as f:
                        json.dump(data, f, indent=4)
                    frame_to_destroy.destroy()
                    del site_widgets[site_name]
                    messagebox.showinfo(check_lang("Успех", "Success"), check_lang(f"2FA ключ для '{site_name}' удалён.", f"2FA key for '{site_name}' deleted."))
            
            button_delete = tk.Button(frame, text=check_lang("Удалить", "Delete"), command=delete_site,
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
        range_of = askinteger(check_lang("Диапазон", "Range"), check_lang("Введите количество символов (например, 10):", "Enter number of characters (e.g., 10):"))
        password = "".join(rand.choice(possible) for _ in range(range_of))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
    def crash(self, event):
        self.destroy()
        
    def show_about(self):
        messagebox.showinfo("О программе", "© PWManager team. MIT License.")
        
    def save_password(self, site, password):
        if not site or not password:
            messagebox.showerror(check_lang("Ошибка", "Error"), check_lang("Поля сайта и пароля не могут быть пустыми!", "Site and password fields cannot be empty!"))
            return
        
        with open(PASSWORDS_FILE, "r") as f:
            data = json.load(f)
        
        if site in data:
            messagebox.showerror(check_lang("Ошибка", "Error"), check_lang("Пароль для этого сайта уже существует!", "Password for this site already exists!"))
            return
        
        encrypted_password = "PWManager-Encrypted-Password-v1.0:" + cipher.encrypt(password.encode()).decode()
        data[site] = encrypted_password

        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo(check_lang("Успех", "Success"), check_lang("Пароль успешно сохранен!", "Password successfully saved!"))

    def delete_password(self, site):
        with open(PASSWORDS_FILE, "r") as f:
            data = json.load(f)
        
        if site not in data:
            messagebox.showerror(check_lang("Ошибка", "Error"), check_lang("Пароль для этого сайта не найден!", "Password for this site not found!"))
            return
        
        if messagebox.askyesno(check_lang("Удаление пароля", "Delete Password"), check_lang("Вы уверены, что хотите удалить этот пароль?", "Are you sure you want to delete this password?")):
            pass
        else:
            messagebox.showinfo(check_lang("Отмена", "Cancel"), check_lang("Удаление пароля отменено.", "Password deletion cancelled."))
            return
        
        del data[site]
        with open(PASSWORDS_FILE, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo(check_lang("Успех", "Success"), check_lang("Пароль успешно удален!", "Password successfully deleted!"))

    def save_gui_password(self):
        site = self.site_entry.get()
        password = self.password_entry.get()
        self.save_password(site, password)

    def delete_gui_password(self):
        site = self.site_entry.get()
        self.delete_password(site)

    def copy_to_clipboard_encrypted(self, site):
        with open(PASSWORDS_FILE, "r") as f:
            data = json.load(f)
        
        if site not in data:
            messagebox.showerror(check_lang("Ошибка", "Error"), check_lang("Пароль для этого сайта не найден!", "Password for this site not found!"))
            return
        
        tocopy = cipher.decrypt(data[site].replace("PWManager-Encrypted-Password-v1.0:", "").replace("PWManager-Encrypted-2FA-v1.0", "").encode()).decode()
        pyperclip.copy(tocopy)
        messagebox.showinfo(check_lang("Успех", "Success"), check_lang("Скопировано в буфер обмена!", "Copied to clipboard!"))


    def view_passwords(self):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            data = {"Ошибка": cipher.encrypt(check_lang("Ошибка декодирования файла паролей.", "Error decoding password file.").encode()).decode()}

        if not data:
            messagebox.showinfo(check_lang("Нет паролей", "No Passwords"), check_lang("Пароли еще не сохранены. Сначала сохраните пароль для любого сайта.", "No passwords saved yet. Save a password for any site first."))
            return

        view_window = tk.Toplevel(self)
        view_window.iconbitmap("icon.ico")
        view_window.title(check_lang("Просмотр паролей (PWManager)", "View Passwords (PWManager)"))
        view_window.geometry("500x500")
        view_window.configure(bg="#1f1f1f")

        canvas = tk.Canvas(view_window, bg="#1f1f1f")
        scrollbar = tk.Scrollbar(view_window, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar_x = tk.Scrollbar(view_window, orient=tk.HORIZONTAL, command=canvas.xview)
        scroll_frame = tk.Frame(canvas, bg="#1f1f1f")

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.configure(xscrollcommand=scrollbar_x.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        for site, encrypted_password in data.items():
            password = cipher.decrypt(encrypted_password.replace("PWManager-Encrypted-Password-v1.0:", ""))
            
            site_label = tk.Label(scroll_frame, text=f"{site}: ", bg="#1f1f1f", fg="white", font=("Arial", 12))
            site_label.pack(side=tk.LEFT)
            
            frame = tk.Frame(scroll_frame, bg="#1f1f1f")
            frame.pack(fill=tk.X, pady=5, padx=10)

            password_var = tk.StringVar(value="*" * len(password))
            is_visible = [False]

            password_label = tk.Label(frame, textvariable=password_var, bg="#1f1f1f", fg="white", font=("Arial", 12))
            password_label.pack(side=tk.LEFT, padx=(0, 5))

            def toggle_password(p=password, var=password_var, flag=is_visible):
                flag[0] = not flag[0]
                var.set(p if flag[0] else "*" * len(p))

            toggle_button = tk.Button(frame, text="N", bg="#2196f3", fg="white", font=("Webdings", 10),
                                    command=toggle_password)
            toggle_button.pack(side=tk.RIGHT, padx=5)

            copy_button = tk.Button(frame, text=check_lang("Копировать", "Copy"), bg="#4caf50", fg="white", font=("Arial", 10),
                                    command=lambda site=site: self.copy_to_clipboard(site))
            copy_button.pack(side=tk.RIGHT, padx=5)
            
            delete_button = tk.Button(frame, text=check_lang("Удалить", "Delete"), bg="#f44336", fg="white", font=("Arial", 10),
                                      command=lambda site=site: self.delete_password(site))
            
            delete_button.pack(side=tk.RIGHT, padx=5)


        scroll_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))
        
        def on_mouse_scroll(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")

        canvas.bind_all("<MouseWheel>", on_mouse_scroll)

if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()