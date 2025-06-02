from tkinter import messagebox, simpledialog
import tkinter as tk

class Extension:
    def __init__(self, password_api):
        self.password_api = password_api
        self.description = "Пример расширения для работы с паролями"
        
    def run(self):
        # Создаем окно для демонстрации
        window = tk.Toplevel()
        window.title("Пример работы с паролями")
        window.geometry("400x300")
        window.configure(bg="#1f1f1f")
        
        # Кнопка для получения всех паролей
        get_all_btn = tk.Button(window, 
                              text="Показать все пароли",
                              command=self.show_all_passwords,
                              bg="#2196f3", fg="white")
        get_all_btn.pack(pady=10)
        
        # Кнопка для получения пароля по сайту
        get_site_btn = tk.Button(window,
                               text="Получить пароль по сайту",
                               command=self.get_site_password,
                               bg="#2196f3", fg="white")
        get_site_btn.pack(pady=10)
        
        # Кнопка для добавления пароля
        add_btn = tk.Button(window,
                          text="Добавить пароль",
                          command=self.add_password,
                          bg="#2196f3", fg="white")
        add_btn.pack(pady=10)
        
        # Кнопка для обновления пароля
        update_btn = tk.Button(window,
                             text="Обновить пароль",
                             command=self.update_password,
                             bg="#2196f3", fg="white")
        update_btn.pack(pady=10)
        
        # Кнопка для удаления пароля
        delete_btn = tk.Button(window,
                             text="Удалить пароль",
                             command=self.delete_password,
                             bg="#2196f3", fg="white")
        delete_btn.pack(pady=10)
        
    def show_all_passwords(self):
        try:
            passwords = self.password_api.get_all_passwords()
            if not passwords:
                messagebox.showinfo("Информация", "Нет сохраненных паролей")
                return
                
            # Создаем окно для отображения паролей
            window = tk.Toplevel()
            window.title("Все пароли")
            window.geometry("400x300")
            window.configure(bg="#1f1f1f")
            
            # Создаем текстовое поле с прокруткой
            text = tk.Text(window, bg="#1f1f1f", fg="white")
            scrollbar = tk.Scrollbar(window, command=text.yview)
            text.configure(yscrollcommand=scrollbar.set)
            
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Добавляем пароли в текстовое поле
            for site, password in passwords.items():
                text.insert(tk.END, f"Сайт: {site}\nПароль: {password}\n\n")
                
            text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            
    def get_site_password(self):
        site = simpledialog.askstring("Ввод", "Введите название сайта:")
        if site:
            try:
                password = self.password_api.get_password(site)
                messagebox.showinfo("Пароль", f"Пароль для {site}: {password}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
                
    def add_password(self):
        site = simpledialog.askstring("Ввод", "Введите название сайта:")
        if site:
            password = simpledialog.askstring("Ввод", "Введите пароль:")
            if password:
                try:
                    self.password_api.add_password(site, password)
                    messagebox.showinfo("Успех", "Пароль успешно добавлен")
                except Exception as e:
                    messagebox.showerror("Ошибка", str(e))
                    
    def update_password(self):
        site = simpledialog.askstring("Ввод", "Введите название сайта:")
        if site:
            new_password = simpledialog.askstring("Ввод", "Введите новый пароль:")
            if new_password:
                try:
                    self.password_api.update_password(site, new_password)
                    messagebox.showinfo("Успех", "Пароль успешно обновлен")
                except Exception as e:
                    messagebox.showerror("Ошибка", str(e))
                    
    def delete_password(self):
        site = simpledialog.askstring("Ввод", "Введите название сайта:")
        if site:
            if messagebox.askyesno("Подтверждение", f"Вы уверены, что хотите удалить пароль для {site}?"):
                try:
                    self.password_api.delete_password(site)
                    messagebox.showinfo("Успех", "Пароль успешно удален")
                except Exception as e:
                    messagebox.showerror("Ошибка", str(e)) 