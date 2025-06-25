import os
import json
import base64
import bcrypt
import getpass
import datetime
import string
import random

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text
from rich.columns import Columns
from rich.style import Style

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Initialize Rich Console
console = Console()

# --- Configuration ---
class Config:
    """Stores application-wide configuration constants."""
    DATA_DIR = os.path.join(os.path.expanduser("~"), ".locknest")
    USERS_FILE = os.path.join(DATA_DIR, "users.json")
    VAULT_FILE_PATTERN = os.path.join(DATA_DIR, "{}_vault.locknest")
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 5 # Lockout duration for failed attempts

# Ensure data directory exists
os.makedirs(Config.DATA_DIR, exist_ok=True)

# --- UI Manager ---
class UIManager:
    """Handles all terminal UI interactions and displays using Rich."""

    def __init__(self, console: Console):
        self.console = console

    def clear_screen(self):
        """Clears the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_banner(self):
        """Displays the LockNest application banner with a hacker-themed look using new ASCII art."""
        self.clear_screen()
        banner_text = Text(
            """
db       .d88b.   .o88b. db   dD d8b   db d88888b .d8888. d888888b 
88      .8P  Y8. d8P  Y8 88 ,8P' 888o  88 88'      88'  YP `~~88~~' 
88      88   88 8P       88,8P   88V8o 88 88ooooo  `8bo.      88   
88      88   88 8b       88`8b   88 V8o88 88~~~~~    `Y8b.    88   
88booo. `8b  d8' Y8b  d8 88 `88. 88  V888 88.      db  8D    88   
Y88888P  `Y88P'   `Y88P' YP   YD VP   V8P Y88888P `8888Y'    YP   
                                                                   
                                                                   
 LockNest Your Secure Terminal Password Vault 🔐
            """, justify="center", style="bold cyan" # Changed banner text style
        )
        self.console.print(Panel(banner_text, border_style="blue", title_align="center", padding=(1, 2))) # Changed border style
        # Add GitHub link right after the banner
        self.console.print(Text("Developed by Aresowl: https://github.com/aresowl/", justify="center", style="dim white italic"))
        self.console.print("\n")

    def display_panel(self, title: str, content: str, style: str = "dim cyan"):
        """Displays a message within a styled Rich Panel."""
        # Adjusted title style to use a more consistent color based on the panel's main style
        title_color = style.split(' ')[-1] if ' ' in style else style
        self.console.print(Panel(content, title=f"[bold {title_color}]{title}[/]", border_style=style, padding=(1, 2)))

    def display_info(self, message: str):
        """Displays an informational message."""
        self.display_panel("INFO", message, style="blue") # Consistent blue for info

    def display_success(self, message: str):
        """Displays a success message."""
        self.display_panel("SUCCESS", message, style="green") # Green for success

    def display_error(self, message: str):
        """Displays an error message."""
        self.display_panel("ERROR", message, style="bold red") # Bold red for errors

    def get_input(self, prompt_text: str, default: str = None) -> str:
        """Gets a string input from the user. Ensures a string is always returned."""
        # Changed prompt color for better readability/professional feel
        response = Prompt.ask(f"[bold cyan]{prompt_text}[/]", default=default) 
        return response if response is not None else "" # Ensure it's always a string

    def get_password_input(self, prompt_text: str) -> str:
        """Gets a password input from the user (hidden). Ensures a string is always returned."""
        # Changed prompt color for better readability/professional feel
        password = getpass.getpass(f"[bold green]{prompt_text}[/]") 
        return password if password is not None else "" # Ensure it's always a string

    def prompt_confirmation(self, prompt_text: str) -> bool:
        """Prompts the user for a yes/no confirmation."""
        # Changed prompt color
        response = Prompt.ask(f"[bold yellow]{prompt_text} (y/n)[/]", choices=["y", "n"], default="n")
        return response.lower() == 'y'

    def display_menu(self, title: str, options: dict):
        """Displays a numbered menu and gets user choice."""
        # Changed title and border style for menu panel
        self.console.print(Panel(f"[bold green]{title}[/]", border_style="green", padding=(1,2)))
        for i, (key, value) in enumerate(options.items(), 1):
            # Changed menu item color
            self.console.print(f"[bold white]{i}.[/] [blue]{value}[/]")
        self.console.print("\n")
        
        while True:
            choice = self.get_input("Enter your choice").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return list(options.keys())[int(choice) - 1]
            else:
                self.display_error("Invalid input. Please enter a valid number from the menu.")

    def display_vault_table(self, vault_data: list):
        """Displays the password vault data in a color-coded table."""
        if not vault_data:
            self.display_info("No entries found in the vault.")
            return

        table = Table(title="[bold green]🔑 Your Password Vault 🔑[/]", # Changed title color
                      style="green", # Changed table style
                      border_style="dim blue", # Changed border style
                      show_lines=True, 
                      header_style="bold underline cyan", # Changed header style
                      row_styles=["dim", ""] # Alternate row styles for readability
                     )
        table.add_column("ID", style="bold yellow", justify="right") # Changed ID color
        table.add_column("Name", style="white", justify="left") # Changed Name color
        table.add_column("Username", style="cyan", justify="left") # Changed Username color
        table.add_column("Password", style="red", justify="left") # Password column remains red for visual alert
        table.add_column("Notes", style="dim white", justify="left") # Changed Notes color

        for i, entry in enumerate(vault_data, 1):
            table.add_row(
                str(i),
                entry.get("name", "N/A"),
                entry.get("username", "N/A"),
                "[dim]********[/]", # IMPORTANT: Passwords are masked for security reasons.
                                         # Displaying them in plain text in a terminal is a significant security risk.
                entry.get("notes", "N/A")
            )
        self.console.print(table)
        self.console.print("\n")
        # Added instruction for revealing passwords
        self.console.print(
            Panel(
                Text("To view or copy a password, select 'Edit Entry' from the Main Menu "
                     "and choose the desired entry. The password will be displayed there for copying.",
                     style="blue italic"),
                title="Hint",
                border_style="dim blue"
            )
        )
        self.console.print("\n")


# --- Encryption Manager ---
class EncryptionManager:
    """Handles encryption and decryption of vault data."""

    def __init__(self):
        self._key = None

    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """
        Derives a cryptographic key from a master password and salt using HKDF.
        The derived key is used for Fernet encryption.
        """
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'locknest-key-derivation',
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
        self._key = key # Store for internal use
        return key

    def get_fernet_instance(self) -> Fernet:
        """Returns a Fernet instance using the derived key."""
        if not self._key:
            raise ValueError("Encryption key not derived. Call derive_key first.")
        return Fernet(self._key)

    def encrypt_data(self, data: str) -> bytes:
        """Encrypts data using the derived key."""
        fernet = self.get_fernet_instance()
        return fernet.encrypt(data.encode('utf-8'))

    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypts data using the derived key."""
        fernet = self.get_fernet_instance()
        return fernet.decrypt(encrypted_data).decode('utf-8')

# --- Auth Manager ---
class AuthManager:
    """Manages user registration, login, and lockout."""

    def __init__(self, ui_manager: UIManager):
        self.ui = ui_manager
        self.users = self._load_users()
        self.failed_attempts = {} # {username: {'count': int, 'last_attempt': datetime}}

    def _load_users(self) -> dict:
        """Loads user data from the users file."""
        if os.path.exists(Config.USERS_FILE):
            with open(Config.USERS_FILE, 'r') as f:
                return json.load(f)
        return {}

    def _save_users(self):
        """Saves user data to the users file."""
        with open(Config.USERS_FILE, 'w') as f:
            json.dump(self.users, f, indent=4)

    def _check_lockout(self, username: str) -> bool:
        """Checks if a user is currently locked out."""
        if username in self.failed_attempts:
            data = self.failed_attempts[username]
            if data['count'] >= Config.MAX_LOGIN_ATTEMPTS:
                time_diff = datetime.datetime.now() - data['last_attempt']
                if time_diff.total_seconds() < Config.LOCKOUT_DURATION_MINUTES * 60:
                    remaining_time = int(Config.LOCKOUT_DURATION_MINUTES * 60 - time_diff.total_seconds())
                    self.ui.display_error(f"This account is locked due to too many failed attempts. Please try again after {remaining_time} seconds.")
                    return True
                else:
                    # Lockout expired, reset attempts
                    self.failed_attempts.pop(username)
        return False

    def _track_failed_attempt(self, username: str):
        """Tracks failed login attempts for a user."""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = {'count': 0, 'last_attempt': datetime.datetime.now()}
        self.failed_attempts[username]['count'] += 1
        self.failed_attempts[username]['last_attempt'] = datetime.datetime.now()
        
        if self.failed_attempts[username]['count'] >= Config.MAX_LOGIN_ATTEMPTS:
            self.ui.display_error(f"Maximum failed attempts reached for {username}. Your account is locked for {Config.LOCKOUT_DURATION_MINUTES} minutes.")

    def register_user(self) -> bool:
        """Handles user registration."""
        self.ui.display_banner()
        self.ui.display_info("📝 Register New User �")

        username = self.ui.get_input("Enter new username").strip()
        if not username:
            self.ui.display_error("Username cannot be empty.")
            return False
        
        if username in self.users:
            self.ui.display_error("This username already exists. Please choose another one.")
            return False

        while True:
            password = self.ui.get_password_input("Enter your master password (this will unlock your vault)")
            if not password:
                self.ui.display_error("Password cannot be empty.")
                continue

            confirm_password = self.ui.get_password_input("Re-enter your master password")
            if password == confirm_password:
                break
            else:
                self.ui.display_error("Passwords do not match. Please try again.")
        
        # Generate a salt for password hashing and key derivation
        user_salt_bytes = os.urandom(16)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        self.users[username] = {
            "hashed_password": hashed_password,
            "user_salt": base64.b64encode(user_salt_bytes).decode('utf-8') # Store salt for key derivation
        }
        self._save_users()
        self.ui.display_success(f"User '{username}' registered successfully.")
        self.ui.get_input("Press Enter to continue...")
        return True

    def login_user(self, encryption_manager: EncryptionManager) -> str | None:
        """Handles user login."""
        self.ui.display_banner()
        self.ui.display_info("🔑 Login to LockNest 🔑")

        username = self.ui.get_input("Enter your username").strip()
        if not username:
            self.ui.display_error("Username cannot be empty.")
            return None

        if self._check_lockout(username):
            return None

        if username not in self.users:
            self.ui.display_error("Username not found.")
            self._track_failed_attempt(username)
            return None

        password = self.ui.get_password_input("Enter your master password")
        
        user_data = self.users[username]
        hashed_password_from_db = user_data["hashed_password"]
        user_salt_from_db = base64.b64decode(user_data["user_salt"])

        if bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db.encode('utf-8')):
            try:
                # Derive the encryption key using the master password and stored user salt
                encryption_manager.derive_key(password, user_salt_from_db)
                self.ui.display_success(f"Login successful: {username}")
                if username in self.failed_attempts:
                    del self.failed_attempts[username] # Clear failed attempts on success
                self.ui.get_input("Press Enter to continue...")
                return username
            except Exception as e:
                self.ui.display_error(f"Error deriving encryption key: {e}")
                self._track_failed_attempt(username)
                return None
        else:
            self.ui.display_error("Invalid password.")
            self._track_failed_attempt(username)
            return None

# --- Password Vault Manager ---
class PasswordVault:
    """Manages encryption, loading, saving, and operations on password entries."""

    def __init__(self, username: str, encryption_manager: EncryptionManager, ui_manager: UIManager):
        self.username = username
        self.encryption_manager = encryption_manager
        self.ui = ui_manager
        self.vault_file = Config.VAULT_FILE_PATTERN.format(username)
        self.vault_data = self._load_vault()

    def _load_vault(self) -> list:
        """Loads and decrypts the user's vault file."""
        if os.path.exists(self.vault_file):
            try:
                with open(self.vault_file, 'rb') as f:
                    encrypted_content = f.read()
                decrypted_json = self.encryption_manager.decrypt_data(encrypted_content)
                return json.loads(decrypted_json)
            except Exception as e:
                self.ui.display_error(f"Error loading or decrypting vault: {e}. The vault might be corrupted or the master password incorrect.")
                return [] # Return empty vault on error
        return []

    def _save_vault(self):
        """Encrypts and saves the user's vault file."""
        try:
            json_data = json.dumps(self.vault_data, indent=4)
            encrypted_data = self.encryption_manager.encrypt_data(json_data)
            with open(self.vault_file, 'wb') as f:
                f.write(encrypted_data)
            self.ui.display_success("Vault saved successfully.")
        except Exception as e:
            self.ui.display_error(f"Error saving or encrypting vault: {e}")

    def add_entry(self):
        """Adds a new password entry to the vault."""
        self.ui.display_banner()
        self.ui.display_info("➕ Add New Entry ➕")
        name = self.ui.get_input("Enter site/service name (e.g., Google, Facebook)").strip()
        if not name:
            self.ui.display_error("Name cannot be empty.")
            self.ui.get_input("Press Enter to continue...")
            return

        username = self.ui.get_input("Enter username/email").strip()
        password = self.ui.get_password_input("Enter password (or leave blank to generate)").strip()

        if not password:
            if self.ui.prompt_confirmation("Do you want to generate a strong password?"):
                password = self._generate_password()
                if password:
                    self.ui.display_info(f"Generated password: [bold green]{password}[/]")
            else:
                self.ui.display_error("Password cannot be empty if not generated.")
                self.ui.get_input("Press Enter to continue...")
                return
        
        self._check_password_strength(password) # Check strength after input/generation

        notes = self.ui.get_input("Enter notes (optional)").strip()

        new_entry = {
            "name": name,
            "username": username,
            "password": password,
            "notes": notes
        }
        self.vault_data.append(new_entry)
        self._save_vault()
        self.ui.display_success(f"Entry '{name}' added successfully.")
        self.ui.get_input("Press Enter to continue...")

    def view_entries(self):
        """Displays all password entries."""
        self.ui.display_banner()
        self.ui.display_vault_table(self.vault_data)
        self.ui.get_input("Press Enter to continue...")

    def edit_entry(self):
        """Edits an existing password entry."""
        self.ui.display_banner()
        if not self.vault_data:
            self.ui.display_info("Vault is empty. No entries to edit.")
            self.ui.get_input("Press Enter to continue...")
            return

        self.ui.display_vault_table(self.vault_data) # Display the table before asking for ID
        
        while True:
            try:
                entry_id = int(self.ui.get_input("Enter the ID of the entry to edit"))
                if 1 <= entry_id <= len(self.vault_data):
                    break
                else:
                    self.ui.display_error("Invalid entry ID.")
            except ValueError:
                self.ui.display_error("Invalid input. Please enter a number.")

        entry_to_edit = self.vault_data[entry_id - 1]
        self.ui.display_info(f"Editing entry: [bold yellow]{entry_to_edit.get('name', 'N/A')}[/]")

        # Display the actual password clearly for the user to copy
        self.ui.display_panel(
            "Current Password (Copy from here):",
            f"[bold green]{entry_to_edit.get('password', 'N/A')}[/]",
            style="green"
        )
        self.ui.console.print("\n") # Add a newline for spacing

        new_name = self.ui.get_input(f"New Name ({entry_to_edit.get('name', '')})", default=entry_to_edit.get('name', ''))
        new_username = self.ui.get_input(f"New Username ({entry_to_edit.get('username', '')})", default=entry_to_edit.get('username', ''))
        
        change_password = self.ui.prompt_confirmation("Do you want to change the password?")
        new_password = entry_to_edit.get('password', '') # Keep old password by default
        if change_password:
            new_password = self.ui.get_password_input("Enter new password (or leave blank to generate)").strip()
            if not new_password:
                if self.ui.prompt_confirmation("Do you want to generate a strong password?"):
                    new_password = self._generate_password()
                    if new_password:
                        self.ui.display_info(f"Generated password: [bold green]{new_password}[/]")
                else:
                    self.ui.display_error("Password cannot be empty if not generated.")
                    self.ui.get_input("Press Enter to continue...")
                    return
            self._check_password_strength(new_password) # Check strength after input/generation

        new_notes = self.ui.get_input(f"New Notes ({entry_to_edit.get('notes', '')})", default=entry_to_edit.get('notes', ''))

        # Only update if new values are provided and not empty, otherwise keep existing
        entry_to_edit["name"] = new_name if new_name else entry_to_edit.get('name', '')
        entry_to_edit["username"] = new_username if new_username else entry_to_edit.get('username', '')
        entry_to_edit["password"] = new_password if new_password else entry_to_edit.get('password', '')
        entry_to_edit["notes"] = new_notes if new_notes else entry_to_edit.get('notes', '')

        self._save_vault()
        self.ui.display_success(f"Entry '{entry_to_edit['name']}' updated successfully.")
        self.ui.get_input("Press Enter to continue...")

    def delete_entry(self):
        """Deletes a password entry from the vault."""
        self.ui.display_banner()
        if not self.vault_data:
            self.ui.display_info("Vault is empty. No entries to delete.")
            self.ui.get_input("Press Enter to continue...")
            return

        self.ui.display_vault_table(self.vault_data)

        while True:
            try:
                entry_id = int(self.ui.get_input("Enter the ID of the entry to delete"))
                if 1 <= entry_id <= len(self.vault_data):
                    break
                else:
                    self.ui.display_error("Invalid entry ID.")
            except ValueError:
                self.ui.display_error("Invalid input. Please enter a number.")

        entry_to_delete = self.vault_data[entry_id - 1]
        if self.ui.prompt_confirmation(f"Are you sure you want to delete entry '{entry_to_delete.get('name', 'N/A')}'?"):
            del self.vault_data[entry_id - 1]
            self._save_vault()
            self.ui.display_success(f"Entry '{entry_to_delete.get('name', 'N/A')}' deleted successfully.")
        else:
            self.ui.display_info("Deletion cancelled.")
        self.ui.get_input("Press Enter to continue...")

    def search_entries(self):
        """Searches for passwords by keyword."""
        self.ui.display_banner()
        if not self.vault_data:
            self.ui.display_info("Vault is empty. No entries to search.")
            self.ui.get_input("Press Enter to continue...")
            return

        keyword = self.ui.get_input("Enter keyword to search").strip().lower()
        if not keyword:
            self.ui.display_error("Search keyword cannot be empty.")
            self.ui.get_input("Press Enter to continue...")
            return

        results = []
        for entry in self.vault_data:
            if (keyword in entry.get("name", "").lower() or
                keyword in entry.get("username", "").lower() or
                keyword in entry.get("notes", "").lower()):
                results.append(entry)
        
        self.ui.display_info(f"Search results for '[bold yellow]{keyword}[/]'")
        self.ui.display_vault_table(results)
        self.ui.get_input("Press Enter to continue...")

    def _generate_password(self) -> str:
        """Generates a strong password based on user preferences."""
        self.ui.display_info("⚙️ Generate Strong Password ⚙️")
        
        while True:
            try:
                length = int(self.ui.get_input("Enter password length (min 8)", default="16"))
                if length < 8:
                    self.ui.display_error("Password length must be at least 8.")
                    continue
                break
            except ValueError:
                self.ui.display_error("Invalid input. Please enter a number.")

        use_uppercase = self.ui.prompt_confirmation("Include uppercase letters? (A-Z)")
        use_lowercase = self.ui.prompt_confirmation("Include lowercase letters? (a-z)")
        use_digits = self.ui.prompt_confirmation("Include digits? (0-9)")
        use_symbols = self.ui.prompt_confirmation("Include symbols? (!@#$%)")

        characters = ""
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation
        
        if not characters:
            self.ui.display_error("You must select at least one character type to generate a password.")
            return ""

        password = ''.join(random.choice(characters) for i in range(length))
        return password

    def _check_password_strength(self, password: str):
        """
        A basic password strength indicator based on common criteria.
        """
        strength = 0
        feedback = []

        if len(password) >= 12:
            strength += 1
            feedback.append("[green]Length: Excellent[/]")
        elif len(password) >= 8:
            strength += 0.5
            feedback.append("[yellow]Length: Good[/]")
        else:
            feedback.append("[red]Length: Too short (min 8 recommended)[/]")

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        if has_lower: strength += 1
        if has_upper: strength += 1
        if has_digit: strength += 1
        if has_symbol: strength += 1

        if has_lower and has_upper and has_digit and has_symbol:
            feedback.append("[green]Complexity: Excellent (Mixed character types)[/]")
        elif (has_lower or has_upper) and has_digit and has_symbol:
            feedback.append("[yellow]Complexity: Good (Letters, numbers, symbols)[/]")
        elif (has_lower or has_upper) and has_digit:
            feedback.append("[orange1]Complexity: Medium (Letters, numbers)[/]")
        else:
            feedback.append("[red]Complexity: Low (Insufficient variety)[/]")
        
        # Changed panel style for password strength to dim magenta for a more professional look
        self.ui.display_panel("Password Strength", "\n".join(feedback), style="dim magenta")

# --- Main Application ---
class LockNestApp:
    """Main application class for LockNest."""

    def __init__(self):
        self.ui = UIManager(console)
        self.auth_manager = AuthManager(self.ui)
        self.encryption_manager = EncryptionManager()
        self.current_user = None
        self.vault = None

    def _main_menu(self):
        """Displays the main menu after successful login."""
        while True:
            self.ui.display_banner()
            self.ui.display_info(f"Welcome to LockNest, [bold green]{self.current_user}[/]!")
            
            menu_options = {
                "add": "Add New Password",
                "view": "View All Passwords",
                "edit": "Edit Entry",
                "delete": "Delete Entry",
                "search": "Search Passwords",
                "logout": "Logout Account",
                "exit": "Exit LockNest"
            }
            choice = self.ui.display_menu("Main Menu", menu_options)

            if choice == "add":
                self.vault.add_entry()
            elif choice == "view":
                self.vault.view_entries()
            elif choice == "edit":
                self.vault.edit_entry()
            elif choice == "delete":
                self.vault.delete_entry()
            elif choice == "search":
                self.vault.search_entries()
            elif choice == "logout":
                self.current_user = None
                self.vault = None
                self.ui.display_success("Successfully logged out.")
                self.ui.get_input("Press Enter to continue...")
                break # Go back to auth menu
            elif choice == "exit":
                self.ui.display_info("Thank you for using LockNest! Goodbye.")
                raise SystemExit # Exit the application

    def run(self):
        """Runs the main application loop."""
        while True:
            if not self.current_user:
                self.ui.display_banner()
                auth_options = {
                    "login": "Login to Account",
                    "register": "Register New User",
                    "exit_app": "Exit Application"
                }
                auth_choice = self.ui.display_menu("Choose an option:", auth_options)

                if auth_choice == "login":
                    logged_in_user = self.auth_manager.login_user(self.encryption_manager)
                    if logged_in_user:
                        self.current_user = logged_in_user
                        self.vault = PasswordVault(self.current_user, self.encryption_manager, self.ui)
                elif auth_choice == "register":
                    self.auth_manager.register_user()
                elif auth_choice == "exit_app":
                    self.ui.display_info("Thank you for using LockNest! Goodbye.")
                    raise SystemExit
            else:
                self._main_menu()

if __name__ == "__main__":
    try:
        app = LockNestApp()
        app.run()
    except SystemExit:
        pass # Graceful exit
    except Exception as e:
        console.print(Panel(f"[bold red]An unexpected error occurred:[/]\n[red]{e}[/]", title="System Error", border_style="red"))
        console.print("[bold yellow]Application is closing...[/]")
�
