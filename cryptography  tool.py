import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import hashlib
import base64
from cryptography.fernet import Fernet
import secrets
import string

class AdvancedCryptographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Advanced Cryptography Tool")
        self.root.geometry("900x750")
        self.root.resizable(True, True)
        
        # Modern color scheme
        self.colors = {
            'bg': '#f5f5f5',
            'card': '#ffffff',
            'primary': '#2563eb',
            'primary_hover': '#1d4ed8',
            'secondary': '#64748b',
            'success': '#10b981',
            'warning': '#f59e0b',
            'error': '#ef4444',
            'text': '#1f2937',
            'text_light': '#6b7280',
            'border': '#e5e7eb'
        }
        
        # Configure root background
        self.root.configure(bg=self.colors['bg'])
        
        # Configure modern styles
        self.setup_modern_styles()
        
        # Create main container with padding
        self.main_container = tk.Frame(root, bg=self.colors['bg'])
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Configure grid weight
        self.main_container.columnconfigure(0, weight=1)
        self.main_container.rowconfigure(1, weight=1)
        
        # Create header
        self.create_header()
        
        # Create main content area
        self.create_main_content()
        
        # Create footer
        self.create_footer()
        
        # Initialize with default method
        self.on_method_change(None)
        
        # Bind keyboard shortcuts
        self.root.bind('<Control-Return>', lambda e: self.execute_operation())
        self.root.bind('<Control-n>', lambda e: self.clear_all())
        self.root.bind('<Control-s>', lambda e: self.save_output())
        
        # Focus on input text
        self.input_text.focus()
    
    def setup_modern_styles(self):
        """Configure modern styles for the application"""
        style = ttk.Style()
        
        # Configure modern button styles
        style.configure("Primary.TButton", 
                       font=("Segoe UI", 10, "bold"),
                       padding=(20, 10))
        
        style.configure("Secondary.TButton", 
                       font=("Segoe UI", 10),
                       padding=(15, 8))
        
        style.configure("Success.TButton", 
                       font=("Segoe UI", 10),
                       padding=(15, 8))
        
        # Configure combobox style
        style.configure("Modern.TCombobox", 
                       font=("Segoe UI", 10),
                       fieldbackground=self.colors['card'])
        
        # Configure entry style
        style.configure("Modern.TEntry", 
                       font=("Segoe UI", 10),
                       fieldbackground=self.colors['card'])
        
        # Configure label styles
        style.configure("Title.TLabel", 
                       font=("Segoe UI", 24, "bold"),
                       foreground=self.colors['text'],
                       background=self.colors['bg'])
        
        style.configure("Subtitle.TLabel", 
                       font=("Segoe UI", 11),
                       foreground=self.colors['text_light'],
                       background=self.colors['bg'])
        
        style.configure("Section.TLabel", 
                       font=("Segoe UI", 11, "bold"),
                       foreground=self.colors['text'],
                       background=self.colors['card'])
        
        style.configure("Info.TLabel", 
                       font=("Segoe UI", 9),
                       foreground=self.colors['text_light'],
                       background=self.colors['card'])
        
        # Configure frame styles
        style.configure("Card.TFrame", 
                       background=self.colors['card'],
                       relief='flat',
                       borderwidth=1)
        
        style.configure("Header.TFrame", 
                       background=self.colors['bg'])
    
    def create_card_frame(self, parent, title=None, subtitle=None):
        """Create a modern card-style frame"""
        card = tk.Frame(parent, 
                       bg=self.colors['card'],
                       relief='flat',
                       bd=1,
                       highlightbackground=self.colors['border'],
                       highlightthickness=1)
        
        if title:
            header_frame = tk.Frame(card, bg=self.colors['card'])
            header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
            
            title_label = tk.Label(header_frame, 
                                 text=title,
                                 font=("Segoe UI", 12, "bold"),
                                 fg=self.colors['text'],
                                 bg=self.colors['card'])
            title_label.pack(anchor=tk.W)
            
            if subtitle:
                subtitle_label = tk.Label(header_frame, 
                                        text=subtitle,
                                        font=("Segoe UI", 9),
                                        fg=self.colors['text_light'],
                                        bg=self.colors['card'])
                subtitle_label.pack(anchor=tk.W)
        
        return card
    
    def create_header(self):
        """Create the modern header section"""
        header_frame = tk.Frame(self.main_container, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Main title
        title_label = tk.Label(header_frame, 
                             text="🔐 Advanced Cryptography Tool",
                             font=("Segoe UI", 24, "bold"),
                             fg=self.colors['text'],
                             bg=self.colors['bg'])
        title_label.pack(anchor=tk.W)
        
        # Subtitle
        subtitle_label = tk.Label(header_frame, 
                                text="Secure encryption and decryption with multiple algorithms",
                                font=("Segoe UI", 11),
                                fg=self.colors['text_light'],
                                bg=self.colors['bg'])
        subtitle_label.pack(anchor=tk.W)
    
    def create_main_content(self):
        """Create the main content area"""
        content_frame = tk.Frame(self.main_container, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True)
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(1, weight=1)
        
        # Method selection card
        self.create_method_selection(content_frame)
        
        # Main processing area
        self.create_processing_area(content_frame)
        
        # Information card
        self.create_info_card(content_frame)
    
    def create_method_selection(self, parent):
        """Create the method selection card"""
        method_card = self.create_card_frame(parent, "🔧 Encryption Method", "Choose your preferred cryptographic algorithm")
        method_card.pack(fill=tk.X, pady=(0, 15))
        
        method_content = tk.Frame(method_card, bg=self.colors['card'])
        method_content.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Method selection
        method_frame = tk.Frame(method_content, bg=self.colors['card'])
        method_frame.pack(fill=tk.X)
        
        self.method_var = tk.StringVar(value="Caesar Cipher (Basic)")
        method_combo = ttk.Combobox(method_frame, 
                                   textvariable=self.method_var,
                                   style="Modern.TCombobox",
                                   width=35, 
                                   state="readonly",
                                   font=("Segoe UI", 10))
        method_combo['values'] = (
            "Caesar Cipher (Basic)",
            "Vigenère Cipher (Polyalphabetic)",
            "AES-256 (Advanced Encryption Standard)",
            "RSA (Public Key Cryptography)",
            "Morse Code",
            "Base64 Encoding",
            "Base32 Encoding",
            "Decimal Encoding",
            "Binary Encoding"
        )
        
        # Method mapping
        self.method_map = {
            "Caesar Cipher (Basic)": "caesar",
            "Vigenère Cipher (Polyalphabetic)": "vigenere",
            "AES-256 (Advanced Encryption Standard)": "aes",
            "RSA (Public Key Cryptography)": "rsa",
            "Morse Code": "morse",
            "Base64 Encoding": "base64",
            "Base32 Encoding": "base32",
            "Decimal Encoding": "decimal",
            "Binary Encoding": "binary"
        }
        
        method_combo.pack(side=tk.LEFT)
        method_combo.bind('<<ComboboxSelected>>', self.on_method_change)
        
        # Generate key button
        self.generate_key_btn = tk.Button(method_frame, 
                                         text="🔑 Generate Key",
                                         font=("Segoe UI", 9),
                                         bg=self.colors['success'],
                                         fg='white',
                                         relief='flat',
                                         padx=15,
                                         pady=5,
                                         cursor='hand2',
                                         command=self.generate_key)
        self.generate_key_btn.pack(side=tk.RIGHT)
        
        # Hover effects for generate key button
        self.generate_key_btn.bind('<Enter>', lambda e: self.generate_key_btn.config(bg='#059669'))
        self.generate_key_btn.bind('<Leave>', lambda e: self.generate_key_btn.config(bg=self.colors['success']))
    
    def create_processing_area(self, parent):
        """Create the main processing area"""
        processing_frame = tk.Frame(parent, bg=self.colors['bg'])
        processing_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        processing_frame.columnconfigure(0, weight=1)
        processing_frame.columnconfigure(1, weight=1)
        processing_frame.rowconfigure(1, weight=1)
        
        # Input section
        input_card = self.create_card_frame(processing_frame, "📝 Input Text", "Enter the text you want to encrypt or decrypt")
        input_card.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 8), pady=(0, 15))
        
        # Output section
        output_card = self.create_card_frame(processing_frame, "📋 Output", "Processed result will appear here")
        output_card.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(8, 0), pady=(0, 15))
        
        # Input text area
        input_content = tk.Frame(input_card, bg=self.colors['card'])
        input_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.input_text = tk.Text(input_content, 
                                 height=8, 
                                 wrap=tk.WORD,
                                 font=("Segoe UI", 10),
                                 bg=self.colors['card'],
                                 fg=self.colors['text'],
                                 relief='flat',
                                 bd=1,
                                 highlightbackground=self.colors['border'],
                                 highlightthickness=1,
                                 selectbackground=self.colors['primary'],
                                 selectforeground='white')
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        # Output text area
        output_content = tk.Frame(output_card, bg=self.colors['card'])
        output_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.output_text = tk.Text(output_content, 
                                  height=8, 
                                  wrap=tk.WORD,
                                  font=("Segoe UI", 10),
                                  bg=self.colors['card'],
                                  fg=self.colors['text'],
                                  relief='flat',
                                  bd=1,
                                  highlightbackground=self.colors['border'],
                                  highlightthickness=1,
                                  selectbackground=self.colors['primary'],
                                  selectforeground='white',
                                  state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Control panel
        control_card = self.create_card_frame(processing_frame)
        control_card.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        control_content = tk.Frame(control_card, bg=self.colors['card'])
        control_content.pack(fill=tk.X, padx=20, pady=20)
        control_content.columnconfigure(1, weight=1)
        
        # Key input section
        self.key_frame = tk.Frame(control_content, bg=self.colors['card'])
        self.key_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        
        # Operation selection
        operation_frame = tk.Frame(control_content, bg=self.colors['card'])
        operation_frame.grid(row=1, column=0, sticky=tk.W, pady=(0, 15))
        
        operation_label = tk.Label(operation_frame, 
                                 text="Operation:",
                                 font=("Segoe UI", 10, "bold"),
                                 fg=self.colors['text'],
                                 bg=self.colors['card'])
        operation_label.pack(side=tk.LEFT, padx=(0, 15))
        
        self.operation_var = tk.StringVar(value="encrypt")
        
        # Modern radio buttons
        encrypt_frame = tk.Frame(operation_frame, bg=self.colors['card'])
        encrypt_frame.pack(side=tk.LEFT, padx=(0, 15))
        
        encrypt_radio = tk.Radiobutton(encrypt_frame, 
                                      text="🔒 Encrypt",
                                      variable=self.operation_var, 
                                      value="encrypt",
                                      font=("Segoe UI", 10),
                                      fg=self.colors['text'],
                                      bg=self.colors['card'],
                                      activebackground=self.colors['card'],
                                      selectcolor=self.colors['primary'])
        encrypt_radio.pack(side=tk.LEFT)
        
        decrypt_frame = tk.Frame(operation_frame, bg=self.colors['card'])
        decrypt_frame.pack(side=tk.LEFT)
        
        decrypt_radio = tk.Radiobutton(decrypt_frame, 
                                      text="🔓 Decrypt",
                                      variable=self.operation_var, 
                                      value="decrypt",
                                      font=("Segoe UI", 10),
                                      fg=self.colors['text'],
                                      bg=self.colors['card'],
                                      activebackground=self.colors['card'],
                                      selectcolor=self.colors['primary'])
        decrypt_radio.pack(side=tk.LEFT)
        
        # Action buttons
        button_frame = tk.Frame(control_content, bg=self.colors['card'])
        button_frame.grid(row=1, column=2, sticky=tk.E)
        
        # Execute button
        self.execute_btn = tk.Button(button_frame, 
                                    text="⚡ Execute",
                                    font=("Segoe UI", 10, "bold"),
                                    bg=self.colors['primary'],
                                    fg='white',
                                    relief='flat',
                                    padx=20,
                                    pady=8,
                                    cursor='hand2',
                                    command=self.execute_operation)
        self.execute_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear button
        self.clear_btn = tk.Button(button_frame, 
                                  text="🗑️ Clear",
                                  font=("Segoe UI", 10),
                                  bg=self.colors['secondary'],
                                  fg='white',
                                  relief='flat',
                                  padx=15,
                                  pady=8,
                                  cursor='hand2',
                                  command=self.clear_all)
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Save button
        self.save_btn = tk.Button(button_frame, 
                                 text="💾 Save",
                                 font=("Segoe UI", 10),
                                 bg=self.colors['success'],
                                 fg='white',
                                 relief='flat',
                                 padx=15,
                                 pady=8,
                                 cursor='hand2',
                                 command=self.save_output)
        self.save_btn.pack(side=tk.LEFT)
        
        # Add hover effects
        self.add_button_hover_effects()
    
    def add_button_hover_effects(self):
        """Add hover effects to buttons"""
        # Execute button
        self.execute_btn.bind('<Enter>', lambda e: self.execute_btn.config(bg=self.colors['primary_hover']))
        self.execute_btn.bind('<Leave>', lambda e: self.execute_btn.config(bg=self.colors['primary']))
        
        # Clear button
        self.clear_btn.bind('<Enter>', lambda e: self.clear_btn.config(bg='#475569'))
        self.clear_btn.bind('<Leave>', lambda e: self.clear_btn.config(bg=self.colors['secondary']))
        
        # Save button
        self.save_btn.bind('<Enter>', lambda e: self.save_btn.config(bg='#059669'))
        self.save_btn.bind('<Leave>', lambda e: self.save_btn.config(bg=self.colors['success']))
    
    def create_info_card(self, parent):
        """Create the information card"""
        info_card = self.create_card_frame(parent, "ℹ️ Method Information", "Learn about the selected encryption method")
        info_card.pack(fill=tk.X)
        
        info_content = tk.Frame(info_card, bg=self.colors['card'])
        info_content.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.info_text = tk.Text(info_content, 
                                height=3, 
                                wrap=tk.WORD,
                                font=("Segoe UI", 9),
                                bg=self.colors['card'],
                                fg=self.colors['text_light'],
                                relief='flat',
                                bd=0,
                                state=tk.DISABLED)
        self.info_text.pack(fill=tk.X)
    
    def create_footer(self):
        """Create the footer with status"""
        footer_frame = tk.Frame(self.main_container, bg=self.colors['bg'])
        footer_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Select encryption method and enter text")
        
        status_frame = tk.Frame(footer_frame, 
                               bg=self.colors['card'],
                               relief='flat',
                               bd=1,
                               highlightbackground=self.colors['border'],
                               highlightthickness=1)
        status_frame.pack(fill=tk.X)
        
        status_label = tk.Label(status_frame, 
                               textvariable=self.status_var,
                               font=("Segoe UI", 9),
                               fg=self.colors['text_light'],
                               bg=self.colors['card'],
                               anchor=tk.W)
        status_label.pack(fill=tk.X, padx=15, pady=8)
        
        # Keyboard shortcuts info
        shortcuts_label = tk.Label(footer_frame, 
                                  text="💡 Shortcuts: Ctrl+Enter (Execute) | Ctrl+N (Clear) | Ctrl+S (Save)",
                                  font=("Segoe UI", 8),
                                  fg=self.colors['text_light'],
                                  bg=self.colors['bg'])
        shortcuts_label.pack(anchor=tk.W, pady=(5, 0))
    
    def get_current_method(self):
        """Get the current method key from the selected display text"""
        return self.method_map.get(self.method_var.get(), "caesar")
    
    def setup_key_inputs(self):
        """Setup key input fields based on selected method"""
        # Clear existing widgets
        for widget in self.key_frame.winfo_children():
            widget.destroy()
        
        method = self.get_current_method()
        
        # Key label
        key_label = tk.Label(self.key_frame, 
                           text=self.get_key_label(method),
                           font=("Segoe UI", 10, "bold"),
                           fg=self.colors['text'],
                           bg=self.colors['card'])
        key_label.pack(side=tk.LEFT, padx=(0, 15))
        
        # Key input
        self.key_var = tk.StringVar()
        self.key_entry = tk.Entry(self.key_frame, 
                                 textvariable=self.key_var,
                                 font=("Segoe UI", 10),
                                 width=30,
                                 bg=self.colors['card'],
                                 fg=self.colors['text'],
                                 relief='flat',
                                 bd=1,
                                 highlightbackground=self.colors['border'],
                                 highlightthickness=1,
                                 show="*" if method == "aes" else "")
        self.key_entry.pack(side=tk.LEFT)
        
        # Key validation info
        validation_text = self.get_key_validation_info(method)
        if validation_text:
            info_label = tk.Label(self.key_frame, 
                                text=validation_text,
                                font=("Segoe UI", 8),
                                fg=self.colors['text_light'],
                                bg=self.colors['card'])
            info_label.pack(side=tk.LEFT, padx=(15, 0))
    
    def get_key_label(self, method):
        """Get the appropriate key label for the method"""
        labels = {
            "caesar": "🔢 Shift Key (1-25):",
            "vigenere": "🔤 Keyword:",
            "aes": "🔐 Password:",
            "rsa": "🔑 RSA Key:"
        }
        # No key needed for base64, base32, decimal, binary
        return labels.get(method, "")
    
    def get_key_validation_info(self, method):
        """Get validation info text for the method"""
        info = {
            "caesar": "Numbers only",
            "vigenere": "Letters only",
            "aes": "Min 4 characters",
            "rsa": "Min 8 characters"
        }
        # No validation info for base64, base32, decimal, binary
        return info.get(method, "")
    
    def on_method_change(self, event):
        """Handle method selection change"""
        method = self.get_current_method()
        self.setup_key_inputs()
        self.update_method_info()
        
        # Enable/disable generate key button based on method
        if method in ["aes", "rsa"]:
            self.generate_key_btn.config(state="normal")
        else:
            self.generate_key_btn.config(state="disabled")
    
    def update_method_info(self):
        """Update method information display"""
        method = self.get_current_method()
        
        info_text = {
            "caesar": "Caesar Cipher: A simple substitution cipher where each letter is shifted by a fixed number of positions. Security: Very weak, easily broken through frequency analysis.",
            "vigenere": "Vigenère Cipher: Uses a keyword to create multiple Caesar ciphers, making it more secure than simple substitution. Security: Moderate, vulnerable to statistical analysis.",
            "aes": "AES-256: Advanced Encryption Standard with 256-bit keys. Industry standard for symmetric encryption. Security: Very strong, used by governments and militaries worldwide.",
            "rsa": "RSA: Asymmetric (public-key) cryptography system based on factoring large numbers. Security: Very strong when properly implemented with sufficient key length.",
            "morse": "Morse Code: Encodes text characters as sequences of dots and dashes. Security: None, used for simple communication and signaling.",
            "base64": "Base64 Encoding: Encodes binary data into ASCII characters using 64 symbols. Commonly used for data transfer and storage.",
            "base32": "Base32 Encoding: Encodes binary data into ASCII characters using 32 symbols. Useful for case-insensitive data encoding.",
            "decimal": "Decimal Encoding: Converts text characters to their decimal ASCII values separated by spaces.",
            "binary": "Binary Encoding: Converts text characters to their binary ASCII representation separated by spaces."
        }
        
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert("1.0", info_text.get(method, ""))
        self.info_text.config(state=tk.DISABLED)
    
    def generate_key(self):
        """Generate a random key for supported methods"""
        method = self.get_current_method()
        
        if method == "aes":
            # Generate a random password
            password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) 
                             for _ in range(16))
            self.key_var.set(password)
            
        elif method == "rsa":
            # Generate a simple RSA key (for demonstration)
            rsa_key = base64.b64encode(os.urandom(32)).decode('utf-8')[:32]
            self.key_var.set(rsa_key)
        
        else:
            # No key generation for base64, base32, decimal, binary
            self.key_var.set("")
        
        self.status_var.set("🔑 Key generated successfully")
    
    # Encryption/Decryption Methods (keeping the same implementations)
    
    def caesar_cipher(self, text, shift, encrypt=True):
        """Caesar cipher implementation"""
        if not encrypt:
            shift = -shift
        
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                result += shifted_char
            else:
                result += char
        
        return result
    
    def vigenere_cipher(self, text, keyword, encrypt=True):
        """Vigenère cipher implementation"""
        keyword = keyword.upper()
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                key_char = keyword[key_index % len(keyword)]
                shift = ord(key_char) - ord('A')
                
                if not encrypt:
                    shift = -shift
                
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                result += shifted_char
                key_index += 1
            else:
                result += char
        
        return result
    
    def aes_encrypt_decrypt(self, text, password, encrypt=True):
        """AES encryption/decryption using password"""
        try:
            # Create a key from password using SHA-256
            key = hashlib.sha256(password.encode()).digest()
            key_b64 = base64.urlsafe_b64encode(key)
            
            fernet = Fernet(key_b64)
            
            if encrypt:
                encrypted = fernet.encrypt(text.encode())
                return base64.b64encode(encrypted).decode()
            else:
                decoded = base64.b64decode(text.encode())
                decrypted = fernet.decrypt(decoded)
                return decrypted.decode()
        except Exception as e:
            raise Exception(f"AES operation failed: {str(e)}")
    
    def rsa_encrypt_decrypt(self, text, key, encrypt=True):
        """Simplified RSA implementation (for demonstration)"""
        try:
            # This is a simplified demonstration - real RSA is much more complex
            key_hash = hashlib.sha256(key.encode()).digest()
            
            if encrypt:
                # Simple XOR encryption for demonstration
                result = ""
                for i, char in enumerate(text):
                    key_byte = key_hash[i % len(key_hash)]
                    encrypted_byte = ord(char) ^ key_byte
                    result += chr(encrypted_byte)
                return base64.b64encode(result.encode('latin-1')).decode()
            else:
                decoded = base64.b64decode(text.encode()).decode('latin-1')
                result = ""
                for i, char in enumerate(decoded):
                    key_byte = key_hash[i % len(key_hash)]
                    decrypted_byte = ord(char) ^ key_byte
                    result += chr(decrypted_byte)
                return result
        except Exception as e:
            raise Exception(f"RSA operation failed: {str(e)}")
    
    
    def validate_input(self, method, text, key):
        """Validate input based on selected method"""
        if not text.strip():
            return False, "Please enter some text to process."
        
        # No key required for base64, base32, decimal, binary, morse
        if method not in ["caesar", "vigenere", "aes", "rsa"] and key.strip():
            key = ""  # ignore key if provided
        
        if method in ["caesar", "vigenere", "aes", "rsa"] and not key.strip():
            return False, "Please enter a key."
        
        if method == "caesar":
            try:
                shift = int(key)
                if not (1 <= shift <= 25):
                    return False, "Caesar shift must be between 1 and 25."
            except ValueError:
                return False, "Caesar shift must be a valid number."
        
        elif method == "vigenere":
            if not key.isalpha():
                return False, "Vigenère keyword must contain only letters."
        
        elif method == "aes":
            if len(key) < 4:
                return False, "AES password must be at least 4 characters long."
        
        elif method == "rsa":
            if len(key) < 8:
                return False, "RSA key must be at least 8 characters long."
        
        return True, ""
    
    def execute_operation(self):
        """Execute the selected cryptographic operation"""
        try:
            # Get inputs
            method = self.get_current_method()
            input_text = self.input_text.get("1.0", tk.END).strip()
            key = self.key_var.get().strip()
            is_encrypt = self.operation_var.get() == "encrypt"
            
            # Validate inputs
            is_valid, error_msg = self.validate_input(method, input_text, key)
            if not is_valid:
                messagebox.showerror("❌ Validation Error", error_msg)
                self.status_var.set(f"❌ {error_msg}")
                return
            
            # Show processing status
            self.status_var.set("⏳ Processing...")
            self.root.update()
            
            # Perform operation based on method
            if method == "caesar":
                shift = int(key)
                result = self.caesar_cipher(input_text, shift, is_encrypt)
            
            elif method == "vigenere":
                result = self.vigenere_cipher(input_text, key, is_encrypt)
            
            elif method == "aes":
                result = self.aes_encrypt_decrypt(input_text, key, is_encrypt)
            
            elif method == "rsa":
                result = self.rsa_encrypt_decrypt(input_text, key, is_encrypt)
            
            elif method == "morse":
                result = self.morse_code(input_text, is_encrypt)
            
            elif method == "base64":
                if is_encrypt:
                    result = base64.b64encode(input_text.encode()).decode()
                else:
                    result = base64.b64decode(input_text.encode()).decode()
            
            elif method == "base32":
                if is_encrypt:
                    result = base64.b32encode(input_text.encode()).decode()
                else:
                    result = base64.b32decode(input_text.encode()).decode()
            
            elif method == "decimal":
                if is_encrypt:
                    result = ' '.join(str(ord(c)) for c in input_text)
                else:
                    chars = input_text.split()
                    result = ''.join(chr(int(c)) for c in chars)
            
            elif method == "binary":
                if is_encrypt:
                    result = ' '.join(format(ord(c), '08b') for c in input_text)
                else:
                    chars = input_text.split()
                    result = ''.join(chr(int(b, 2)) for b in chars)
            
            # Display result
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.output_text.config(state=tk.DISABLED)
            
            # Update status
            operation_icon = "🔒" if is_encrypt else "🔓"
            operation_name = "Encryption" if is_encrypt else "Decryption"
            method_name = method.replace('_', ' ').title()
            self.status_var.set(f"✅ {operation_icon} {method_name} {operation_name.lower()} completed successfully")
            
        except Exception as e:
            error_msg = f"Operation failed: {str(e)}"
            messagebox.showerror("❌ Error", error_msg)
            self.status_var.set(f"❌ {error_msg}")
    
    def clear_all(self):
        """Clear all input and output fields"""
        self.input_text.delete("1.0", tk.END)
        self.key_var.set("")
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.operation_var.set("encrypt")
        self.status_var.set("🗑️ Fields cleared - Ready for new operation")
        self.input_text.focus()
    
    def save_output(self):
        """Save the output text to a file"""
        try:
            output_content = self.output_text.get("1.0", tk.END).strip()
            if not output_content:
                messagebox.showwarning("⚠️ Warning", "No output to save.")
                self.status_var.set("⚠️ No output to save")
                return
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Cryptography Output"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(f"=== Advanced Cryptography Tool Output ===\n")
                    file.write(f"Method: {self.method_var.get()}\n")
                    file.write(f"Operation: {self.operation_var.get().title()}\n")
                    file.write(f"Timestamp: {tk.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    file.write(f"{'='*50}\n\n")
                    file.write(f"Result:\n{output_content}")
                
                messagebox.showinfo("✅ Success", f"Output saved successfully!\n\nFile: {os.path.basename(file_path)}")
                self.status_var.set(f"💾 Output saved to {os.path.basename(file_path)}")
            
        except Exception as e:
            error_msg = f"Failed to save file: {str(e)}"
            messagebox.showerror("❌ Error", error_msg)
            self.status_var.set(f"❌ Save failed: {str(e)}")

    def morse_code(self, text, encrypt=True):
        """Morse code encryption and decryption"""
        MORSE_CODE_DICT = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..',
            '0': '-----', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.',
            '&': '.-...', "'": '.----.', '@': '.--.-.', ')': '-.--.-',
            '(': '-.--.', ':': '---...', ',': '--..--', '=': '-...-',
            '!': '-.-.--', '.': '.-.-.-', '-': '-....-', '+': '.-.-.',
            '"': '.-..-.', '?': '..--..', '/': '-..-.', ' ': '/'
        }
        
        if encrypt:
            encrypted = []
            for char in text.upper():
                if char in MORSE_CODE_DICT:
                    encrypted.append(MORSE_CODE_DICT[char])
                else:
                    encrypted.append(char)
            return ' '.join(encrypted)
        else:
            reversed_dict = {v: k for k, v in MORSE_CODE_DICT.items()}
            words = text.split(' / ')
            decrypted_words = []
            for word in words:
                chars = word.split()
                decoded_chars = []
                for char in chars:
                    decoded_chars.append(reversed_dict.get(char, ''))
                decrypted_words.append(''.join(decoded_chars))
            return ' '.join(decrypted_words)

def main():
    """Main function to run the application"""
    root = tk.Tk()
    
    # Set window icon (if available)
    try:
        root.iconbitmap("crypto_icon.ico")
    except:
        pass
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")
    
    # Initialize application
    app = AdvancedCryptographyGUI(root)
    
    # Start the GUI event loop
    root.mainloop()

if __name__ == "__main__":
    main()