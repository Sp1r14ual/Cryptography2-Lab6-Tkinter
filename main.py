import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import hashlib
import time
from collections import defaultdict
import re

# Функция для создания хэша пароля


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Настройка SQLAlchemy
DATABASE_URL = 'sqlite:///app.db'
Base = declarative_base()
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Определение модели пользователя


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)

# Определение модели товара


class Product(Base):
    __tablename__ = 'products'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    price = Column(Float, nullable=False)


# Лимит на количество неудачных попыток входа
MAX_FAILED_ATTEMPTS = 5
BLOCK_TIME = 60  # Время блокировки в секундах

# Словарь для отслеживания попыток входа
# [количество попыток, время первой попытки]
login_attempts = defaultdict(lambda: [0, 0])

# Класс для приложения


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Highly Secure CRUD App")

        # Установка начального размера окна
        self.root.geometry('600x500')

        # Создание стилей
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TLabel', font=('Helvetica', 12))
        self.style.configure('TButton', font=('Helvetica', 12, 'bold'))
        self.style.configure('Blue.TButton', font=(
            'Helvetica', 12, 'bold'), background='#0000FF', foreground='white')
        self.style.configure('Red.TButton', font=(
            'Helvetica', 12, 'bold'), background='#FF0000', foreground='white')
        self.style.configure('Green.TButton', font=(
            'Helvetica', 12, 'bold'), background='#008000', foreground='white')
        self.style.configure('TEntry', font=('Helvetica', 12))
        self.style.configure('TFrame', background='#D3D3D3')
        self.style.configure('TLabelFrame', font=(
            'Helvetica', 14, 'bold'), background='#D3D3D3')

        self.create_login_screen()

    # Создание экрана входа
    def create_login_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill='both')

        ttk.Label(frame, text="Username").pack(pady=10)
        self.username_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.username_entry.pack(pady=10)

        ttk.Label(frame, text="Password").pack(pady=10)
        self.password_entry = tk.Entry(
            frame, show="*", font=('Helvetica', 12), justify='center')
        self.password_entry.pack(pady=10)

        ttk.Button(frame, text="Login", command=self.authenticate_user,
                   style='Green.TButton').pack(pady=10)
        ttk.Button(frame, text="Register", command=self.create_register_screen,
                   style='Green.TButton').pack(pady=10)

    # Очистка экрана
    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # Проверка попыток входа для защиты от DoS
    def check_login_attempts(self, username):
        current_time = time.time()
        attempts, first_attempt_time = login_attempts[username]

        if attempts >= MAX_FAILED_ATTEMPTS:
            if current_time - first_attempt_time < BLOCK_TIME:
                return False
            else:
                login_attempts[username] = [0, 0]

        return True

    # Аутентификация пользователя
    def authenticate_user(self):
        username = self.username_entry.get()
        password = hash_password(self.password_entry.get())

        if len(username) > 50 or len(password) > 64:
            messagebox.showerror("Error", "Input exceeds maximum length")
            return

        if not self.check_login_attempts(username):
            messagebox.showerror(
                "Error", "Too many failed attempts. Try again later.")
            return

        user = session.query(User).filter_by(
            username=username, password=password).first()

        if user:
            login_attempts[username] = [0, 0]
            self.user_role = user.role
            self.create_main_screen()
        else:
            login_attempts[username][0] += 1
            if login_attempts[username][0] == 1:
                login_attempts[username][1] = time.time()
            messagebox.showerror("Error", "Invalid credentials")

    # Создание экрана регистрации
    def create_register_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill='both')

        ttk.Label(frame, text="New Username").pack(pady=10)
        self.new_username_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.new_username_entry.pack(pady=10)

        ttk.Label(frame, text="New Password").pack(pady=10)
        self.new_password_entry = tk.Entry(
            frame, show="*", font=('Helvetica', 12), justify='center')
        self.new_password_entry.pack(pady=10)

        self.role_var = "user"  # Зафиксируем роль пользователя

        ttk.Button(frame, text="Register", command=self.register_user,
                   style='Green.TButton').pack(pady=10)
        ttk.Button(frame, text="Back to Login", command=self.create_login_screen,
                   style='Green.TButton').pack(pady=10)

    # Регистрация пользователя
    def register_user(self):
        new_username = self.new_username_entry.get()
        new_password = hash_password(self.new_password_entry.get())
        role = self.role_var

        if len(new_username) > 50 or len(new_password) > 64:
            messagebox.showerror("Error", "Input exceeds maximum length")
            return

        # Проверка наличия запрещенных символов в имени пользователя
        if not re.match(r'^[\w.@+-]+$', new_username):
            messagebox.showerror("Error", "Invalid characters in username")
            return

        new_user = User(username=new_username,
                        password=new_password, role=role)
        session.add(new_user)
        try:
            session.commit()
            messagebox.showinfo("Success", "Registration successful")
            self.create_login_screen()
        except:
            session.rollback()
            messagebox.showerror("Error", "Username already exists")

    # Создание главного экрана
    def create_main_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill='both')

        ttk.Label(frame, text=f"Welcome, {self.user_role}").pack(pady=10)
        ttk.Button(frame, text="View Products", command=self.view_products,
                   style='Green.TButton').pack(pady=10)

        if self.user_role == 'admin':
            ttk.Button(frame, text="Add Product", command=self.add_product,
                       style='Blue.TButton').pack(pady=10)
            ttk.Button(frame, text="Edit Product", command=self.edit_product,
                       style='Blue.TButton').pack(pady=10)
            ttk.Button(frame, text="Delete Product",
                       command=self.delete_product, style='Red.TButton').pack(pady=10)

        ttk.Button(frame, text="Logout", command=self.create_login_screen,
                   style='Red.TButton').pack(pady=10)

    # Просмотр товаров
    def view_products(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill='both')

        products = session.query(Product).all()
        for product in products:
            ttk.Label(frame, text=f"ID: {product.id}, Name: {product.name}, Description: {
                      product.description}, Price: {product.price}").pack(pady=5)

        ttk.Button(frame, text="Back", command=self.create_main_screen,
                   style='Green.TButton').pack(pady=10)

    # Добавление товара (только для администраторов)
    def add_product(self):
        if self.user_role != 'admin':
            messagebox.showerror("Error", "Permission denied")
            return

        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill='both')

        ttk.Label(frame, text="Product Name").pack(pady=10)
        self.product_name_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.product_name_entry.pack(pady=10)

        ttk.Label(frame, text="Product Description").pack(pady=10)
        self.product_description_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.product_description_entry.pack(pady=10)

        ttk.Label(frame, text="Product Price").pack(pady=10)
        self.product_price_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.product_price_entry.pack(pady=10)

        ttk.Button(frame, text="Add Product", command=self.save_product,
                   style='Blue.TButton').pack(pady=10)
        ttk.Button(frame, text="Back", command=self.create_main_screen,
                   style='Green.TButton').pack(pady=10)

    def save_product(self):
        name = self.product_name_entry.get()
        description = self.product_description_entry.get()
        try:
            price = float(self.product_price_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid price")
            return

        if len(name) > 50 or len(description) > 255:
            messagebox.showerror("Error", "Input exceeds maximum length")
            return

        new_product = Product(name=name, description=description, price=price)
        session.add(new_product)
        try:
            session.commit()
            messagebox.showinfo("Success", "Product added successfully")
            self.create_main_screen()
        except:
            session.rollback()
            messagebox.showerror("Error", "Failed to add product")

    # Изменение товара (только для администраторов)
    def edit_product(self):
        if self.user_role != 'admin':
            messagebox.showerror("Error", "Permission denied")
            return

        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill='both')

        ttk.Label(frame, text="Product ID").pack(pady=10)
        self.edit_product_id_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.edit_product_id_entry.pack(pady=10)

        ttk.Label(frame, text="New Name").pack(pady=10)
        self.edit_product_name_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.edit_product_name_entry.pack(pady=10)

        ttk.Label(frame, text="New Description").pack(pady=10)
        self.edit_product_description_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.edit_product_description_entry.pack(pady=10)

        ttk.Label(frame, text="New Price").pack(pady=10)
        self.edit_product_price_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.edit_product_price_entry.pack(pady=10)

        ttk.Button(frame, text="Update Product",
                   command=self.update_product, style='Blue.TButton').pack(pady=10)
        ttk.Button(frame, text="Back", command=self.create_main_screen,
                   style='Green.TButton').pack(pady=10)

    def update_product(self):
        product_id = self.edit_product_id_entry.get()
        new_name = self.edit_product_name_entry.get()
        new_description = self.edit_product_description_entry.get()
        try:
            new_price = float(self.edit_product_price_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid price")
            return

        if len(new_name) > 50 or len(new_description) > 255:
            messagebox.showerror("Error", "Input exceeds maximum length")
            return

        product = session.query(Product).filter_by(id=product_id).first()
        if product:
            product.name = new_name
            product.description = new_description
            product.price = new_price
            try:
                session.commit()
                messagebox.showinfo("Success", "Product updated successfully")
                self.create_main_screen()
            except:
                session.rollback()
                messagebox.showerror("Error", "Failed to update product")
        else:
            messagebox.showerror("Error", "Product not found")

    # Удаление товара (только для администраторов)
    def delete_product(self):
        if self.user_role != 'admin':
            messagebox.showerror("Error", "Permission denied")
            return

        self.clear_screen()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill='both')

        ttk.Label(frame, text="Product ID").pack(pady=10)
        self.delete_product_id_entry = tk.Entry(
            frame, font=('Helvetica', 12), justify='center')
        self.delete_product_id_entry.pack(pady=10)

        ttk.Button(frame, text="Delete Product",
                   command=self.remove_product, style='Red.TButton').pack(pady=10)
        ttk.Button(frame, text="Back", command=self.create_main_screen,
                   style='Green.TButton').pack(pady=10)

    def remove_product(self):
        product_id = self.delete_product_id_entry.get()

        if len(product_id) > 10:
            messagebox.showerror("Error", "Input exceeds maximum length")
            return

        product = session.query(Product).filter_by(id=product_id).first()
        if product:
            session.delete(product)
            try:
                session.commit()
                messagebox.showinfo("Success", "Product deleted successfully")
                self.create_main_screen()
            except:
                session.rollback()
                messagebox.showerror("Error", "Failed to delete product")
        else:
            messagebox.showerror("Error", "Product not found")


# Создание базы данных
Base.metadata.create_all(engine)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
