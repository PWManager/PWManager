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
import sys
import re
import importlib.util
from PIL import Image, ImageTk
from win10toast import ToastNotifier

def get_system_language():
    # Try the new recommended approach first
    try:
        lang, _ = locale.getlocale()
        if lang:
            return "ru" if lang == "Russian_Russia" else "en"
    except:
        pass

KEY_FILE = "crypt.key"
TWOFACTORFILE = "2fa.json"
PASSWORDS_FILE = "passwords.json"
ACHIEVEMENTS_FILE = "achievements.json"
achievements = []

if not os.path.exists(ACHIEVEMENTS_FILE):
    with open(ACHIEVEMENTS_FILE, "w") as f:
        json.dump([], f)
else:
    with open(ACHIEVEMENTS_FILE, "r") as f:
        achievements = json.load(f)

if not os.path.exists("crypt.key"):
    key = Fernet.generate_key()
    try:
        with open("crypt.key", "wb") as key_file:
            key_file.write(key)
    except Exception as e:
        key = Fernet.generate_key().decode()
else:
    key = open("crypt.key", "rb").read()

cipher = Fernet(key)

if not os.path.exists(PASSWORDS_FILE):
    with open(PASSWORDS_FILE, "w") as f:
        json.dump({}, f)
        
if not os.path.exists(TWOFACTORFILE):
    with open(TWOFACTORFILE, "w") as f:
        json.dump({}, f)
        
class GuiFunctions:
    def truncate_text(self, text, length):
        return text if len(text) <= length else text[:length - 3] + "..."
    
    def new_achievement(self, title, description):
        try:
            with open(ACHIEVEMENTS_FILE, "r", encoding="utf-8") as f:
                achievements = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            achievements = []

        if not any(item["title"] == title for item in achievements):
            signature = f"{rand.randint(0, 9)}{base64.b64encode(f"{sys.version}".encode()).decode()}"
            achievements.append({"title": title, "description": description, "signature": signature})
            
            with open(ACHIEVEMENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(achievements, f, indent=4, ensure_ascii=False)
            
            toast = ToastNotifier()
            toast.show_toast(
                title,
                description,
                icon_path="icon.ico",\
                duration=2,
                threaded=True
            )
    
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

class PasswordAPI:
    def __init__(self, cipher):
        self.cipher = cipher
        self.passwords_file = PASSWORDS_FILE
        
    def get_all_passwords(self):
        """Get all passwords as a dictionary {site: password}"""
        try:
            with open(self.passwords_file, "r") as f:
                data = json.load(f)
            return {site: self.cipher.decrypt(encrypted.replace("PWManager-Encrypted-Password-v1.0:", "").encode()).decode()
                   for site, encrypted in data.items()}
        except Exception as e:
            raise Exception(f"Error getting passwords: {str(e)}")
            
    def get_password(self, site):
        """Get password for specific site"""
        try:
            with open(self.passwords_file, "r") as f:
                data = json.load(f)
            if site not in data:
                raise Exception(f"Password for {site} not found")
            return self.cipher.decrypt(data[site].replace("PWManager-Encrypted-Password-v1.0:", "").encode()).decode()
        except Exception as e:
            raise Exception(f"Error getting password: {str(e)}")
            
    def add_password(self, site, password):
        """Add new password"""
        try:
            with open(self.passwords_file, "r") as f:
                data = json.load(f)
            if site in data:
                raise Exception(f"Password for {site} already exists")
            encrypted_password = "PWManager-Encrypted-Password-v1.0:" + self.cipher.encrypt(password.encode()).decode()
            data[site] = encrypted_password
            with open(self.passwords_file, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            raise Exception(f"Error adding password: {str(e)}")
            
    def update_password(self, site, new_password):
        """Update existing password"""
        try:
            with open(self.passwords_file, "r") as f:
                data = json.load(f)
            if site not in data:
                raise Exception(f"Password for {site} not found")
            encrypted_password = "PWManager-Encrypted-Password-v1.0:" + self.cipher.encrypt(new_password.encode()).decode()
            data[site] = encrypted_password
            with open(self.passwords_file, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            raise Exception(f"Error updating password: {str(e)}")
            
    def delete_password(self, site):
        """Delete password"""
        try:
            with open(self.passwords_file, "r") as f:
                data = json.load(f)
            if site not in data:
                raise Exception(f"Password for {site} not found")
            del data[site]
            with open(self.passwords_file, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            raise Exception(f"Error deleting password: {str(e)}")

class ExtensionManager:
    def __init__(self, cipher):
        self.extensions = {}
        self.extensions_dir = "extensions"
        self.password_api = PasswordAPI(cipher)
        self.ensure_extensions_dir()
        
    def ensure_extensions_dir(self):
        if not os.path.exists(self.extensions_dir):
            os.makedirs(self.extensions_dir)
            
    def load_extensions(self):
        self.extensions.clear()
        for filename in os.listdir(self.extensions_dir):
            if filename.endswith('.py'):
                try:
                    module_name = filename[:-3]
                    file_path = os.path.join(self.extensions_dir, filename)
                    
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    if hasattr(module, 'Extension'):
                        extension = module.Extension(self.password_api)
                        self.extensions[module_name] = extension
                except Exception as e:
                    print(f"Error loading extension {filename}: {str(e)}")
                    
    def run_extension(self, extension_name):
        if extension_name in self.extensions:
            try:
                self.extensions[extension_name].run()
            except Exception as e:
                messagebox.showerror(check_lang("Ошибка расширения", "Extension Error"), 
                                   f"{check_lang('Ошибка при запуске расширения:', 'Error running extension:')} {str(e)}")
        else:
            messagebox.showerror(check_lang("Ошибка", "Error"), 
                               check_lang("Расширение не найдено", "Extension not found"))

class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PWManager")
        self.geometry("500x660")
        self.iconbitmap("icon.ico")  # Make sure the icon.ico file exists in the same directory
        self.resizable(False, False)
        self.config(bg="#1f1f1f")
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        
        # Initialize extension manager with cipher
        self.extension_manager = ExtensionManager(cipher)
        self.extension_manager.load_extensions()
        
        # Bind Shift+F8 to extension menu
        self.bind("<Shift-F8>", self.show_extension_menu)
        
        self.site_label = tk.Label(self, text=check_lang("Сайт:", "Site:"), bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_label.pack(pady=10)

        self.site_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.site_entry.pack(pady=10)

        self.password_label = tk.Label(self, text=check_lang("Пароль:", "Password:"), bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_label.pack(pady=10)

        self.password_entry = tk.Entry(self, bg="#1f1f1f", fg="white", font=("Arial", 16))
        self.password_entry.pack(pady=10)
        
        # Add password strength indicator
        self.strength_frame = tk.Frame(self, bg="#1f1f1f")
        self.strength_frame.pack(pady=5)
        
        self.strength_label = tk.Label(self.strength_frame, text=check_lang("Сила пароля:", "Password Strength:"), 
                                     bg="#1f1f1f", fg="white", font=("Arial", 12))
        self.strength_label.pack(side=tk.LEFT, padx=5)
        
        self.strength_indicator = tk.Label(self.strength_frame, text="", bg="#1f1f1f", fg="white", font=("Arial", 12))
        self.strength_indicator.pack(side=tk.LEFT, padx=5)
        
        # Bind password entry to strength check
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)

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
            
            GuiFunctions.new_achievement(self, check_lang("Опа а что тут?", "Oops, what's here?"), check_lang("Пользователь крашнул программу!", "User crash program!"))
            
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

    def check_password_strength(self, event=None):
        password = self.password_entry.get()
        if not password:
            self.strength_indicator.config(text="", fg="white")
            return
            
        # Initialize score
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append(check_lang("Длина менее 8 символов", "Length less than 8 characters"))
            
        # Uppercase check
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append(check_lang("Нет заглавных букв", "No uppercase letters"))
            
        # Lowercase check
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append(check_lang("Нет строчных букв", "No lowercase letters"))
            
        # Numbers check
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append(check_lang("Нет цифр", "No numbers"))
            
        # Special characters check
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append(check_lang("Нет специальных символов", "No special characters"))
            
        # Set strength indicator
        if score == 0:
            strength = check_lang("Очень слабый", "Very Weak")
            color = "#ff0000"  # Red
        elif score == 1:
            strength = check_lang("Слабый", "Weak")
            color = "#ff6b6b"  # Light Red
        elif score == 2:
            strength = check_lang("Средний", "Medium")
            color = "#ffd700"  # Gold
        elif score == 3:
            strength = check_lang("Хороший", "Good")
            color = "#90ee90"  # Light Green
        elif score == 4:
            strength = check_lang("Сильный", "Strong")
            color = "#32cd32"  # Lime Green
        else:
            strength = check_lang("Очень сильный", "Very Strong")
            color = "#008000"  # Green
            
        self.strength_indicator.config(text=strength, fg=color)
        
        # Add tooltip with feedback
        if feedback:
            tooltip_text = "\n".join(feedback)
            self.strength_indicator.config(text=f"{strength} ({tooltip_text})")

    def show_extension_menu(self, event=None):
        extension_window = tk.Toplevel(self)
        extension_window.title(check_lang("Расширения", "Extensions"))
        extension_window.geometry("400x500")
        extension_window.iconbitmap("icon.ico")
        extension_window.configure(bg="#1f1f1f")
        
        # Add title
        title_label = tk.Label(extension_window, 
                             text=check_lang("Доступные расширения:", "Available Extensions:"),
                             bg="#1f1f1f", fg="white", font=("Arial", 14))
        title_label.pack(pady=10)
        
        # Create scrollable frame for extensions
        canvas = tk.Canvas(extension_window, bg="#1f1f1f")
        scrollbar = tk.Scrollbar(extension_window, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg="#1f1f1f")
        
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        
        # Add extension buttons
        for ext_name, extension in self.extension_manager.extensions.items():
            frame = tk.Frame(scroll_frame, bg="#1f1f1f")
            frame.pack(fill=tk.X, pady=5, padx=10)
            
            # Extension name and description
            info_frame = tk.Frame(frame, bg="#1f1f1f")
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            name_label = tk.Label(info_frame, text=ext_name, 
                                bg="#1f1f1f", fg="white", font=("Arial", 12))
            name_label.pack(anchor="w")
            
            if hasattr(extension, 'description'):
                desc_label = tk.Label(info_frame, text=extension.description,
                                    bg="#1f1f1f", fg="gray", font=("Arial", 10))
                desc_label.pack(anchor="w")
            
            # Run button
            run_button = tk.Button(frame, 
                                 text=check_lang("Запустить", "Run"),
                                 bg="#2196f3", fg="white",
                                 command=lambda name=ext_name: self.extension_manager.run_extension(name))
            run_button.pack(side=tk.RIGHT, padx=5)
        
        # Add refresh button
        refresh_button = tk.Button(extension_window,
                                 text=check_lang("Обновить список", "Refresh List"),
                                 bg="#4caf50", fg="white",
                                 command=lambda: self.refresh_extensions(extension_window))
        refresh_button.pack(pady=10)
        
        # Configure scrolling
        scroll_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))
        
        def on_mouse_scroll(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")
        
        canvas.bind_all("<MouseWheel>", on_mouse_scroll)
        
    def refresh_extensions(self, window=None):
        self.extension_manager.load_extensions()
        if window:
            window.destroy()
        self.show_extension_menu()

if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()