# Руководство по созданию расширений для PWManager

## Содержание
1. [Введение](#введение)
2. [Структура расширения](#структура-расширения)
3. [Работа с паролями](#работа-с-паролями)
4. [Примеры расширений](#примеры-расширений)
5. [Лучшие практики](#лучшие-практики)

## Введение

PWManager поддерживает систему расширений, которая позволяет добавлять новый функционал к менеджеру паролей. Расширения - это Python-файлы, которые размещаются в директории `extensions/` и автоматически загружаются при запуске программы.

## Структура расширения

Базовое расширение должно содержать класс `Extension` со следующим минимальным кодом:

```python
class Extension:
    def __init__(self, password_api):
        self.password_api = password_api
        self.description = "Описание вашего расширения"
        
    def run(self):
        # Ваш код здесь
        pass
```

### Обязательные компоненты:
- `__init__(self, password_api)` - конструктор, получает API для работы с паролями
- `description` - описание расширения, которое будет показано в меню расширений
- `run()` - метод, который выполняется при запуске расширения

## Работа с паролями

Расширения получают доступ к паролям через `password_api`. Вот основные методы:

### Получение паролей
```python
# Получить все пароли
passwords = self.password_api.get_all_passwords()

# Получить пароль для конкретного сайта
password = self.password_api.get_password("example.com")
```

### Управление паролями
```python
# Добавить новый пароль
self.password_api.add_password("example.com", "password123")

# Обновить существующий пароль
self.password_api.update_password("example.com", "newpassword123")

# Удалить пароль
self.password_api.delete_password("example.com")
```

## Примеры расширений

### 1. Простое расширение с GUI
```python
from tkinter import messagebox, simpledialog
import tkinter as tk

class Extension:
    def __init__(self, password_api):
        self.password_api = password_api
        self.description = "Простое расширение с GUI"
        
    def run(self):
        window = tk.Toplevel()
        window.title("Моё расширение")
        window.geometry("300x200")
        window.configure(bg="#1f1f1f")
        
        button = tk.Button(window, 
                         text="Показать пароли",
                         command=self.show_passwords,
                         bg="#2196f3", fg="white")
        button.pack(pady=20)
        
    def show_passwords(self):
        passwords = self.password_api.get_all_passwords()
        messagebox.showinfo("Пароли", str(passwords))
```

### 2. Расширение для экспорта паролей
```python
import json
from tkinter import filedialog

class Extension:
    def __init__(self, password_api):
        self.password_api = password_api
        self.description = "Экспорт паролей в JSON"
        
    def run(self):
        passwords = self.password_api.get_all_passwords()
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(passwords, f, indent=4)
```

## Лучшие практики

1. **Безопасность**
   - Не храните пароли в открытом виде
   - Используйте предоставленный API для работы с паролями
   - Обрабатывайте все возможные ошибки

2. **Интерфейс**
   - Следуйте темному стилю приложения (bg="#1f1f1f")
   - Используйте стандартные цвета кнопок (#2196f3)
   - Добавляйте понятные описания действий

3. **Обработка ошибок**
   ```python
   try:
       # Ваш код
   except Exception as e:
       messagebox.showerror("Ошибка", str(e))
   ```

4. **Документация**
   - Добавляйте комментарии к коду
   - Описывайте назначение расширения
   - Указывайте требования к системе

## Советы по разработке

1. **Тестирование**
   - Тестируйте расширение перед публикацией
   - Проверяйте обработку ошибок
   - Убедитесь, что интерфейс удобен

2. **Производительность**
   - Избегайте длительных операций в основном потоке
   - Используйте асинхронные операции при необходимости
   - Оптимизируйте работу с большими объемами данных

3. **Совместимость**
   - Проверяйте работу на разных версиях Python
   - Учитывайте возможные изменения в API
   - Следите за обновлениями PWManager

## Полезные ресурсы

- [Документация tkinter](https://docs.python.org/3/library/tkinter.html)
- [Руководство по стилю Python](https://www.python.org/dev/peps/pep-0008/)