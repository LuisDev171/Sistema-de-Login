
import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import secrets
import hmac
import re
import time
from pathlib import Path


# ==========================================
# CONFIGURAÇÕES
# ==========================================

DB_PATH = Path(__file__).resolve().parent / "usuarios.db"

ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

MAX_LOGIN_ATTEMPTS = 5
LOCK_SECONDS = 30

BG = "#101827"
PANEL = "#1c293b"
BLUE = "#4778e6"
WHITE = "#ffffff"
TEXT = "#dbe5f3"
GRAY = "#aab7ca"


# ==========================================
# BANCO DE DADOS
# ==========================================

class Database:

    def __init__(self):
        self.connection = sqlite3.connect(DB_PATH)
        self.connection.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self):

        with self.connection:
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

    @staticmethod
    def hash_password(password, salt):
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            ITERATIONS
        )

    def register(self, name, email, password):

        name = name.strip()
        email = email.strip().lower()

        if len(name) < 2:
            return False, "Digite um nome válido."

        if len(name) > 80:
            return False, "O nome é muito longo."

        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            return False, "Digite um e-mail válido."

        if len(email) > 254:
            return False, "E-mail muito longo."

        if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
            return False, "A senha deve ter entre 8 e 128 caracteres."

        salt = secrets.token_bytes(16)

        password_hash = self.hash_password(
            password,
            salt
        )

        try:
            with self.connection:
                self.connection.execute("""
                    INSERT INTO users
                    (name, email, salt, password_hash)
                    VALUES (?, ?, ?, ?)
                """, (name, email, salt, password_hash))

            return True, "Conta criada com sucesso!"

        except sqlite3.IntegrityError:
            return False, "Este e-mail já está cadastrado."

        except sqlite3.Error:
            return False, "Erro ao salvar os dados."

    def login(self, email, password):

        email = email.strip().lower()

        user = self.connection.execute("""
            SELECT * FROM users WHERE email = ?
        """, (email,)).fetchone()

        if user is None:
            return None

        password_hash = self.hash_password(
            password,
            user["salt"]
        )

        if not hmac.compare_digest(
            password_hash,
            user["password_hash"]
        ):
            return None

        return {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }

    def change_password(self, user_id, old_password, new_password):

        if not MIN_PASSWORD_LENGTH <= len(new_password) <= MAX_PASSWORD_LENGTH:
            return False, "A senha deve ter entre 8 e 128 caracteres."

        user = self.connection.execute("""
            SELECT salt, password_hash
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        if user is None:
            return False, "Usuário não encontrado."

        old_hash = self.hash_password(
            old_password,
            user["salt"]
        )

        if not hmac.compare_digest(
            old_hash,
            user["password_hash"]
        ):
            return False, "Senha atual incorreta."

        new_salt = secrets.token_bytes(16)

        new_hash = self.hash_password(
            new_password,
            new_salt
        )

        with self.connection:
            self.connection.execute("""
                UPDATE users
                SET salt = ?, password_hash = ?
                WHERE id = ?
            """, (new_salt, new_hash, user_id))

        return True, "Senha alterada com sucesso!"

    def close(self):
        self.connection.close()


# ==========================================
# APLICATIVO
# ==========================================

class LoginSystem:

    def __init__(self, root):

        self.root = root
        self.db = Database()

        self.current_user = None

        self.failed_attempts = {}
        self.locked_until = {}

        self.root.title("Sistema de Login")
        self.root.geometry("480x570")
        self.root.minsize(420, 500)
        self.root.configure(bg=BG)

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_app
        )

        self.show_login()

    # ======================================
    # ELEMENTOS DA INTERFACE
    # ======================================

    def clear_screen(self):

        for widget in self.root.winfo_children():
            widget.destroy()

    def make_title(self, title, subtitle):

        tk.Label(
            self.root,
            text=title,
            font=("Segoe UI", 25, "bold"),
            fg=WHITE,
            bg=BG
        ).pack(pady=(35, 5))

        tk.Label(
            self.root,
            text=subtitle,
            font=("Segoe UI", 10),
            fg=GRAY,
            bg=BG
        ).pack(pady=(0, 22))

    def make_label(self, text):

        tk.Label(
            self.root,
            text=text,
            font=("Segoe UI", 10, "bold"),
            fg=TEXT,
            bg=BG,
            anchor="w"
        ).pack(fill="x", padx=65, pady=(9, 5))

    def make_entry(self, password=False):

        entry = tk.Entry(
            self.root,
            font=("Segoe UI", 11),
            bg=PANEL,
            fg=WHITE,
            insertbackground=WHITE,
            relief="flat",
            show="*" if password else ""
        )

        entry.pack(
            fill="x",
            padx=65,
            ipady=10
        )

        return entry

    def make_button(self, text, command, secondary=False):

        color = "#2b3b52" if secondary else BLUE

        tk.Button(
            self.root,
            text=text,
            command=command,
            font=("Segoe UI", 10, "bold"),
            bg=color,
            fg=WHITE,
            activebackground="#365fba",
            activeforeground=WHITE,
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=10
        ).pack(
            fill="x",
            padx=65,
            pady=(16, 0)
        )

    # ======================================
    # TELA DE LOGIN
    # ======================================

    def show_login(self):

        self.clear_screen()

        self.make_title(
            "Bem-vindo!",
            "Entre na sua conta para continuar"
        )

        self.make_label("E-mail")
        self.email_entry = self.make_entry()

        self.make_label("Senha")
        self.password_entry = self.make_entry(password=True)

        self.make_button(
            "ENTRAR",
            self.login
        )

        self.make_button(
            "CRIAR CONTA",
            self.show_register,
            secondary=True
        )

        self.password_entry.bind(
            "<Return>",
            lambda event: self.login()
        )

        self.email_entry.focus_set()

    # ======================================
    # TELA DE CADASTRO
    # ======================================

    def show_register(self):

        self.clear_screen()

        self.make_title(
            "Criar conta",
            "Preencha os dados abaixo"
        )

        self.make_label("Nome")
        self.name_entry = self.make_entry()

        self.make_label("E-mail")
        self.email_entry = self.make_entry()

        self.make_label("Senha (mínimo de 8 caracteres)")
        self.password_entry = self.make_entry(password=True)

        self.make_label("Confirmar senha")
        self.confirm_entry = self.make_entry(password=True)

        self.make_button(
            "CADASTRAR",
            self.register
        )

        self.make_button(
            "VOLTAR AO LOGIN",
            self.show_login,
            secondary=True
        )

    def register(self):

        name = self.name_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        confirmation = self.confirm_entry.get()

        if password != confirmation:
            messagebox.showerror(
                "Cadastro",
                "As senhas não são iguais."
            )
            return

        success, message = self.db.register(
            name,
            email,
            password
        )

        if success:

            messagebox.showinfo(
                "Cadastro",
                message
            )

            self.show_login()

        else:

            messagebox.showerror(
                "Cadastro",
                message
            )

    # ======================================
    # AUTENTICAÇÃO
    # ======================================

    def login(self):

        email = self.email_entry.get().strip().lower()
        password = self.password_entry.get()

        if not email or not password:

            messagebox.showwarning(
                "Login",
                "Preencha o e-mail e a senha."
            )

            return

        now = time.time()

        locked_time = self.locked_until.get(email, 0)

        if now < locked_time:

            remaining = int(locked_time - now) + 1

            messagebox.showwarning(
                "Aguarde",
                f"Tente novamente em {remaining} segundos."
            )

            return

        user = self.db.login(email, password)

        if user is None:

            attempts = self.failed_attempts.get(email, 0) + 1

            self.failed_attempts[email] = attempts

            if attempts >= MAX_LOGIN_ATTEMPTS:

                self.locked_until[email] = time.time() + LOCK_SECONDS
                self.failed_attempts[email] = 0

                messagebox.showerror(
                    "Bloqueado",
                    "Muitas tentativas incorretas.\n"
                    f"Aguarde {LOCK_SECONDS} segundos."
                )

            else:

                remaining = MAX_LOGIN_ATTEMPTS - attempts

                messagebox.showerror(
                    "Falha no login",
                    "E-mail ou senha incorretos.\n"
                    f"Tentativas restantes: {remaining}"
                )

            return

        self.failed_attempts.pop(email, None)
        self.locked_until.pop(email, None)

        self.current_user = user

        self.show_home()

    # ======================================
    # TELA PRINCIPAL
    # ======================================

    def show_home(self):

        self.clear_screen()

        user = self.current_user

        self.make_title(
            "Login realizado!",
            f"Olá, {user['name']}!"
        )

        info = (
            "Você entrou no sistema com sucesso!\n\n"
            f"Nome: {user['name']}\n\n"
            f"E-mail: {user['email']}\n\n"
            "Esta é sua área inicial."
        )

        tk.Label(
            self.root,
            text=info,
            font=("Segoe UI", 11),
            fg=TEXT,
            bg=PANEL,
            justify="left",
            padx=25,
            pady=25
        ).pack(
            fill="x",
            padx=40,
            pady=25
        )

        self.make_button(
            "ALTERAR SENHA",
            self.show_change_password
        )

        self.make_button(
            "SAIR DA CONTA",
            self.logout,
            secondary=True
        )

    # ======================================
    # ALTERAÇÃO DE SENHA
    # ======================================

    def show_change_password(self):

        self.clear_screen()

        self.make_title(
            "Alterar senha",
            "Confirme sua senha atual"
        )

        self.make_label("Senha atual")
        self.old_password_entry = self.make_entry(password=True)

        self.make_label("Nova senha")
        self.new_password_entry = self.make_entry(password=True)

        self.make_label("Confirmar nova senha")
        self.confirm_new_entry = self.make_entry(password=True)

        self.make_button(
            "SALVAR NOVA SENHA",
            self.change_password
        )

        self.make_button(
            "VOLTAR",
            self.show_home,
            secondary=True
        )

    def change_password(self):

        old_password = self.old_password_entry.get()
        new_password = self.new_password_entry.get()
        confirmation = self.confirm_new_entry.get()

        if new_password != confirmation:

            messagebox.showerror(
                "Alterar senha",
                "A confirmação não confere."
            )

            return

        if new_password == old_password:

            messagebox.showwarning(
                "Alterar senha",
                "Escolha uma senha diferente da atual."
            )

            return

        success, message = self.db.change_password(
            self.current_user["id"],
            old_password,
            new_password
        )

        if success:

            messagebox.showinfo(
                "Alterar senha",
                message
            )

            self.show_home()

        else:

            messagebox.showerror(
                "Alterar senha",
                message
            )

    # ======================================
    # SAIR DA CONTA
    # ======================================

    def logout(self):

        self.current_user = None

        self.show_login()

    # ======================================
    # ENCERRAR APLICAÇÃO
    # ======================================

    def close_app(self):

        self.db.close()

        self.root.destroy()


# ==========================================
# INICIALIZAÇÃO
# ==========================================

if __name__ == "__main__":

    root = tk.Tk()

    app = LoginSystem(root)

    root.mainloop()
