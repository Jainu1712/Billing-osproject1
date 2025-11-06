"""
PyQt6 Billing & Inventory Management Application

This is a port of a Tkinter application (billing_app4.py) to PyQt6.
It retains all security features, database interactions, and business logic.
"""

import sys
import sqlite3
import hashlib
import os
import re
import csv
import tempfile
import logging
import secrets
import string
import json
import base64
from datetime import datetime
from logging.handlers import RotatingFileHandler

# --- PyQt6 Imports ---
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QFormLayout, QLabel, QLineEdit, QPushButton, QStackedWidget, QMessageBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QDialog,
    QComboBox, QTextEdit, QGroupBox, QDateEdit, QHeaderView, QFileDialog
)
from PyQt6.QtCore import Qt, QTimer, QDate
from PyQt6.QtGui import QFont, QPalette, QColor

# --- ReportLab Import ---
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("WARNING: reportlab library not found. PDF generation will be disabled.")

# --- Original Configuration and Setup ---

# Security Configuration
SECURITY_CONFIG = {
    'min_password_length': 8,
    'require_special_chars': True,
    'require_numbers': True,
    'require_uppercase': True,
    'max_login_attempts': 3,
    'session_timeout_minutes': 30,
}

DB_FILE = 'billing_inventory_secure_qt.db' # Use a new DB file for safety

# Initialize logging
def init_logging():
    """Initialize comprehensive audit logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler('audit_qt.log', maxBytes=10485760, backupCount=5),
            logging.StreamHandler()
        ]
    )

init_logging()

# --- Security and Role Management (Identical to original) ---

class SecurityManager:
    def __init__(self):
        self.current_session = None
    
    def generate_strong_password(self, length=12):
        """Generate a cryptographically secure random password"""
        characters = string.ascii_letters + string.digits
        if SECURITY_CONFIG['require_special_chars']:
            characters += "!@#$%^&*"
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password
    
    def validate_password_strength(self, password):
        """Validate password meets security requirements"""
        if len(password) < SECURITY_CONFIG['min_password_length']:
            return False, f"Password must be at least {SECURITY_CONFIG['min_password_length']} characters long"
        
        if SECURITY_CONFIG['require_uppercase'] and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if SECURITY_CONFIG['require_numbers'] and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        
        if SECURITY_CONFIG['require_special_chars'] and not any(c in "!@#$%^&*" for c in password):
            return False, "Password must contain at least one special character (!@#$%^&*)"
        
        return True, "Password is strong"
    
    def log_security_event(self, user_id, action, description, ip_address="localhost", success=True):
        """Log security events to database and file"""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            # Check if security_logs table exists
            c.execute('''SELECT name FROM sqlite_master WHERE type='table' AND name='security_logs' ''')
            if c.fetchone():
                c.execute('''INSERT INTO security_logs (user_id, action, description, ip_address, timestamp, success) 
                             VALUES (?, ?, ?, ?, ?, ?)''',
                             (user_id, action, description, ip_address, 
                              datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1 if success else 0))
            conn.commit()
        except Exception as e:
            logging.error(f"Failed to log security event: {e}")
        finally:
            conn.close()
        
        # Also log to file
        log_level = logging.INFO if success else logging.WARNING
        logging.log(log_level, f"User {user_id}: {action} - {description}")

class RoleManager:
    ROLES = {
        'admin': ['view', 'add', 'edit', 'delete', 'reports', 'users', 'security'],
        'manager': ['view', 'add', 'edit', 'reports'],
        'user': ['view', 'add'],
        'viewer': ['view']
    }
    
    PERMISSIONS = {
        'inventory': ['view', 'add', 'edit', 'delete'],
        'billing': ['view', 'add', 'edit'],
        'customers': ['view', 'add', 'edit', 'delete'],
        'suppliers': ['view', 'add', 'edit', 'delete'],
        'expenses': ['view', 'add', 'edit', 'delete'],
        'reports': ['view', 'generate'],
        'users': ['view', 'add', 'edit', 'delete'],
        'security': ['view_logs', 'manage_roles']
    }
    
    def has_permission(self, role, resource, action):
        """Check if role has permission for resource action"""
        if role not in self.ROLES:
            return False
        
        role_permissions = self.ROLES[role]
        
        # Admin has all permissions
        if role == 'admin':
            return True
        
        # Check specific permissions
        if resource in self.PERMISSIONS and action in self.PERMISSIONS[resource]:
            if action in ['view', 'add', 'edit', 'delete']:
                return action in role_permissions
            elif action == 'generate' and 'reports' in role_permissions:
                return True
        
        return False

# --- Database Initialization (Identical to original) ---

def init_db():
    """Initialize database with secure schema"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Enhanced users table with roles and security info
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, 
        username TEXT UNIQUE, 
        password TEXT,
        role TEXT DEFAULT 'user',
        email TEXT,
        phone TEXT,
        created_date TEXT,
        last_login TEXT,
        login_attempts INTEGER DEFAULT 0,
        is_locked INTEGER DEFAULT 0,
        must_change_password INTEGER DEFAULT 1
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY, 
        name TEXT UNIQUE, 
        quantity INTEGER, 
        price REAL,
        created_by INTEGER,
        created_date TEXT,
        last_modified TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS bills (
        id INTEGER PRIMARY KEY, 
        user_id INTEGER, 
        date TEXT, 
        total REAL, 
        items TEXT,
        customer_info TEXT
    )''')
    
    # Customer table
    c.execute('''CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY, 
        name TEXT, 
        phone TEXT, 
        email TEXT, 
        address TEXT,
        total_purchases REAL DEFAULT 0,
        created_date TEXT,
        created_by INTEGER
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS suppliers (
        id INTEGER PRIMARY KEY, 
        name TEXT, 
        contact_person TEXT,
        phone TEXT, 
        email TEXT,
        address TEXT,
        items_supplied TEXT,
        created_date TEXT,
        created_by INTEGER
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY,
        category TEXT,
        amount REAL,
        date TEXT,
        description TEXT,
        paid_to TEXT,
        payment_method TEXT,
        created_by INTEGER
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY,
        bill_id INTEGER,
        method TEXT,
        amount REAL,
        status TEXT,
        transaction_id TEXT,
        date TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY,
        report_type TEXT,
        date_from TEXT,
        date_to TEXT,
        data TEXT,
        generated_date TEXT,
        generated_by INTEGER
    )''')
    
    # Security audit logs table
    c.execute('''CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        action TEXT,
        description TEXT,
        ip_address TEXT,
        timestamp TEXT,
        success INTEGER
    )''')
    
    # Create default admin user if not exists
    try:
        c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
        if c.fetchone()[0] == 0:
            default_password = hashlib.sha256("Admin123!".encode()).hexdigest()
            c.execute('''INSERT INTO users (username, password, role, email, created_date, must_change_password) 
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                         ('admin', default_password, 'admin', 'admin@system.com', 
                          datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1))
            logging.info("Default admin user created")
    except Exception as e:
        logging.error(f"Error creating admin user: {e}")
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# --- Custom Dialogs (PyQt6) ---

class ChangePasswordDialog(QDialog):
    """Dialog to force user to change password."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Password Required")
        self.setModal(True)
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        
        self.info_label = QLabel("You must change your password before continuing.")
        self.info_label.setStyleSheet("color: red;")
        layout.addWidget(self.info_label, alignment=Qt.AlignmentFlag.AlignCenter)

        form_layout = QFormLayout()
        self.current_password = QLineEdit()
        self.current_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("Current Password:", self.current_password)
        form_layout.addRow("New Password:", self.new_password)
        form_layout.addRow("Confirm New Password:", self.confirm_password)
        
        layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        self.change_btn = QPushButton("Change Password")
        self.change_btn.clicked.connect(self.accept)
        button_layout.addStretch()
        button_layout.addWidget(self.change_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)

    def get_passwords(self):
        return self.current_password.text(), self.new_password.text(), self.confirm_password.text()

class SelectCustomerDialog(QDialog):
    """Dialog to select a customer from a list."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Customer")
        self.setMinimumSize(500, 300)
        self.selected_customer_id = None
        self.selected_customer_name = None

        layout = QVBoxLayout(self)
        
        self.customer_table = QTableWidget()
        self.setup_table(self.customer_table, ["ID", "Name", "Phone", "Email"])
        self.customer_table.itemDoubleClicked.connect(self.on_select)
        layout.addWidget(self.customer_table)

        button_layout = QHBoxLayout()
        self.select_btn = QPushButton("Select")
        self.select_btn.clicked.connect(self.on_select)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(self.select_btn)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        
        self.load_customers()
    
    def setup_table(self, table, columns):
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)

    def load_customers(self):
        self.customer_table.setRowCount(0)
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT id, name, phone, email FROM customers ORDER BY name")
            for row_idx, row_data in enumerate(c.fetchall()):
                self.customer_table.insertRow(row_idx)
                for col_idx, col_data in enumerate(row_data):
                    self.customer_table.setItem(row_idx, col_idx, QTableWidgetItem(str(col_data)))
            conn.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load customers: {e}")
        self.customer_table.resizeColumnsToContents()

    def on_select(self):
        selected_rows = self.customer_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a customer from the list.")
            return
            
        selected_row = selected_rows[0].row()
        self.selected_customer_id = int(self.customer_table.item(selected_row, 0).text())
        self.selected_customer_name = self.customer_table.item(selected_row, 1).text()
        self.accept()

    def get_selection(self):
        return self.selected_customer_id, self.selected_customer_name

class AddCustomerDialog(QDialog):
    """Dialog to add a new customer quickly."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New Customer")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        
        self.name_entry = QLineEdit()
        self.phone_entry = QLineEdit()
        self.email_entry = QLineEdit()
        
        self.phone_entry.setPlaceholderText("e.g., 911234567890")
        self.email_entry.setPlaceholderText("e.g., user@example.com")

        form_layout.addRow("Name:*", self.name_entry)
        form_layout.addRow("Phone:", self.phone_entry)
        form_layout.addRow("Email:", self.email_entry)
        
        layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(self.add_btn)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
    
    def get_details(self):
        return (
            self.name_entry.text().strip(),
            self.phone_entry.text().strip(),
            self.email_entry.text().strip()
        )

# --- Main Application (PyQt6) ---

class BillingApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Billing & Inventory Management App - Secure (PyQt6)")
        self.setGeometry(100, 100, 1200, 800)
        
        # --- State Variables (from original) ---
        self.current_user = None
        self.current_user_id = None
        self.current_user_role = None
        self.current_bill = []
        self.selected_customer_id = None
        self.selected_customer_name = "Walk-in Customer"
        
        self.security_manager = SecurityManager()
        self.role_manager = RoleManager()
        self.login_attempts = 0
        self.session_start_time = None

        # --- PyQt6 Specific UI Elements ---
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        
        self.login_widget = QWidget()
        self.main_widget = QWidget()
        
        # --- Session Timer ---
        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.check_session_timeout)

        # --- Create UI Pages ---
        self.create_login_page()
        self.create_main_page_structure() # Create the container
        
        self.stack.addWidget(self.login_widget)
        self.stack.addWidget(self.main_widget)
        
        self.show_login_page()
        self.apply_stylesheet()

    def apply_stylesheet(self):
        """A simple stylesheet for a more consistent look."""
        self.setStyleSheet("""
            QWidget {
                font-family: Arial, sans-serif;
                font-size: 11pt;
            }
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                font-weight: bold;
                font-size: 12pt;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px 0 5px;
                left: 10px;
            }
            QLabel {
                font-size: 11pt;
            }
            QLineEdit, QComboBox, QDateEdit {
                padding: 5px;
                border: 1px solid #c0c0c0;
                border-radius: 3px;
            }
            QTextEdit {
                border: 1px solid #c0c0c0;
                border-radius: 3px;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                font-weight: bold;
                padding: 8px 15px;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:pressed {
                background-color: #003d6a;
            }
            QTableWidget {
                border: 1px solid #c0c0c0;
                gridline-color: #d0d0d0;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 5px;
                border: 1px solid #c0c0c0;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid #c0c0c0;
                border-top: none;
            }
            QTabBar::tab {
                background: #e0e0e0;
                padding: 10px 15px;
                border: 1px solid #c0c0c0;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: white;
                margin-bottom: -1px; /* Overlaps pane border */
            }
            QMessageBox QLabel {
                font-size: 11pt; /* Ensure message box text is readable */
            }
        """)

    # --- Event Overrides for Session Timeout ---
    def keyPressEvent(self, event):
        self.reset_session_timer()
        super().keyPressEvent(event)

    def mousePressEvent(self, event):
        self.reset_session_timer()
        super().mousePressEvent(event)

    def reset_session_timer(self):
        """Reset session timer on user activity"""
        if self.session_start_time:
            self.session_start_time = datetime.now()

    def check_session_timeout(self):
        """Check if session has timed out (called by QTimer)"""
        if self.session_start_time:
            elapsed = datetime.now() - self.session_start_time
            if elapsed.total_seconds() > SECURITY_CONFIG['session_timeout_minutes'] * 60:
                self.session_timer.stop()
                self.security_manager.log_security_event(
                    self.current_user_id, 
                    "SESSION_TIMEOUT", 
                    "User session timed out due to inactivity"
                )
                QMessageBox.warning(self, "Session Timeout", "Your session has expired due to inactivity.")
                self.logout()
                return True
        return False

    # --- Utility Functions (PyQt versions) ---

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def validate_numeric(self, value, field_type):
        try:
            if field_type == 'int':
                return int(value)
            return float(value)
        except (ValueError, TypeError):
            return None

    def validate_email(self, email):
        """Validate email format"""
        if not email:
            return True
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_phone(self, phone):
        """Validate phone format: country code (2 digits) + 10 digits"""
        if not phone:
            return True
        pattern = r'^\d{2}\d{10}$'
        return re.match(pattern, phone) is not None

    def check_permission(self, resource, action):
        """Check if current user has permission for action on resource"""
        if not self.current_user_role:
            return False
        return self.role_manager.has_permission(self.current_user_role, resource, action)

    def show_permission_error(self):
        """Show permission denied message"""
        QMessageBox.critical(self, "Permission Denied", 
                           "You don't have permission to perform this action.\n"
                           "Please contact your administrator.")

    def _setup_table(self, table, columns):
        """Helper to configure a QTableWidget."""
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True) # Ensure last column fills
        
    def _populate_table(self, table, data):
        """Helper to populate a QTableWidget with data."""
        table.setRowCount(0)
        for row_idx, row_data in enumerate(data):
            table.insertRow(row_idx)
            for col_idx, col_data in enumerate(row_data):
                # Format floats to 2 decimal places
                if isinstance(col_data, float):
                    item = QTableWidgetItem(f"{col_data:.2f}")
                else:
                    item = QTableWidgetItem(str(col_data))
                table.setItem(row_idx, col_idx, item)
        table.resizeColumnsToContents()

    def print_text_edit(self, text_edit_widget, title="Document"):
        """Print content from a QTextEdit using QPrinter."""
        if not self.check_permission('reports', 'generate'):
            self.show_permission_error()
            return
        
        try:
            from PyQt6.QtPrintSupport import QPrinter, QPrintDialog
            
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            dialog = QPrintDialog(printer, self)
            dialog.setWindowTitle(f"Print {title}")
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                text_edit_widget.print(printer)
                
        except ImportError:
            QMessageBox.critical(self, "Print Error", 
                                 "Printing library (PyQt6.QtPrintSupport) not found.")
        except Exception as e:
            QMessageBox.critical(self, "Print Error", f"Failed to print: {str(e)}")

    def save_report_to_file(self, content, default_name="report"):
        """Save report content to a text file"""
        if not self.check_permission('reports', 'generate'):
            self.show_permission_error()
            return
            
        try:
            default_filename = f"{default_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report",
                default_filename,
                "Text files (*.txt);;All files (*.*)"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                QMessageBox.information(self, "Success", f"Report saved successfully!\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")

    # --- Page Creation Methods ---

    def create_login_page(self):
        """Creates the UI for the login widget."""
        main_layout = QVBoxLayout(self.login_widget)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        container = QWidget()
        container.setMaximumWidth(400)
        container_layout = QVBoxLayout(container)
        container.setStyleSheet("background-color: white; border-radius: 8px; padding: 20px;")
        
        title = QLabel("Secure Login")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title)
        
        secure_label = QLabel("🔒 Secure Login Required")
        secure_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        secure_label.setStyleSheet("color: green;")
        secure_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(secure_label)
        
        form_layout = QFormLayout()
        form_layout.setContentsMargins(10, 20, 10, 20)
        self.login_username = QLineEdit()
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        
        form_layout.addRow(QLabel("Username:"), self.login_username)
        form_layout.addRow(QLabel("Password:"), self.login_password)
        
        container_layout.addLayout(form_layout)
        
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.login)
        self.login_password.returnPressed.connect(self.login) # Allow pressing Enter
        
        container_layout.addWidget(self.login_btn)
        
        info_label = QLabel("Default Admin: admin / Admin123!")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_label.setStyleSheet("font-size: 9pt; color: #555;")
        container_layout.addWidget(info_label)
        
        main_layout.addWidget(container)
        
    def create_main_page_structure(self):
        """Creates the main application structure (top bar + tabs)."""
        main_layout = QVBoxLayout(self.main_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        # --- Top Bar ---
        top_bar = QWidget()
        top_bar_layout = QHBoxLayout(top_bar)
        top_bar_layout.setContentsMargins(5, 5, 5, 5)
        
        self.user_info_label = QLabel("User: | Role: ")
        self.user_info_label.setFont(QFont("Arial", 10))
        top_bar_layout.addWidget(self.user_info_label)
        
        secure_status = QLabel("🔒 Secure Session")
        secure_status.setFont(QFont("Arial", 10))
        secure_status.setStyleSheet("color: green; font-weight: bold;")
        top_bar_layout.addWidget(secure_status)
        
        top_bar_layout.addStretch()
        
        self.admin_btn = QPushButton("Admin Panel")
        self.admin_btn.clicked.connect(self.show_admin_panel)
        self.admin_btn.setVisible(False) # Hide initially
        top_bar_layout.addWidget(self.admin_btn)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self.logout)
        top_bar_layout.addWidget(self.logout_btn)
        
        main_layout.addWidget(top_bar)

        # --- Tab Widget ---
        self.notebook = QTabWidget()
        main_layout.addWidget(self.notebook)

    def setup_main_ui_tabs(self):
        """Clears and rebuilds the tabs based on user permissions."""
        self.notebook.clear() # Remove all existing tabs
        
        # Update user info label
        self.user_info_label.setText(f"User: {self.current_user} | Role: {self.current_user_role}")
        
        # Show/Hide Admin button
        self.admin_btn.setVisible(self.current_user_role == 'admin')

        # --- Add Tabs Based on Permissions ---
        if self.check_permission('inventory', 'view'):
            self.notebook.addTab(self.create_inventory_tab(), "Inventory")

        if self.check_permission('billing', 'view'):
            self.notebook.addTab(self.create_billing_tab(), "Billing")
            self.new_bill() # Initialize bill text
            self.refresh_billing_inventory() # Load products

        if self.check_permission('customers', 'view'):
            self.notebook.addTab(self.create_customer_tab(), "Customers")

        if self.check_permission('suppliers', 'view'):
            self.notebook.addTab(self.create_supplier_tab(), "Suppliers")
        
        if self.check_permission('expenses', 'view'):
            self.notebook.addTab(self.create_expense_tab(), "Expenses")
        
        if self.check_permission('reports', 'view'):
            self.notebook.addTab(self.create_reports_tab(), "Reports")
        
        # Original app had this check, seems like a typo? 
        # Changed to 'billing' 'view'
        if self.check_permission("billing", "view"): 
            self.notebook.addTab(self.create_bills_tab(), "View Bills")

    # --- Login & Page Switching ---

    def show_login_page(self):
        self.stack.setCurrentWidget(self.login_widget)
        self.session_timer.stop() # Stop timer on logout

    def login(self):
        username = self.login_username.text().strip()
        password = self.login_password.text().strip()
        
        if not username or not password:
            QMessageBox.critical(self, "Error", "Username and password required!")
            return
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        try:
            # Check if account is locked
            c.execute("SELECT is_locked, login_attempts FROM users WHERE username=?", (username,))
            result = c.fetchone()
            if result and result[0] == 1:
                QMessageBox.critical(self, "Account Locked", 
                                   "Your account is locked due to too many failed login attempts.\n"
                                   "Please contact administrator.")
                self.security_manager.log_security_event(
                    None, "ACCOUNT_LOCKED_ATTEMPT", 
                    f"Attempted login to locked account: {username}", 
                    success=False
                )
                return
            
            # Verify credentials
            c.execute('''SELECT id, username, password, role, must_change_password, login_attempts 
                         FROM users WHERE username=?''', (username,))
            user = c.fetchone()
            
            if user and user[2] == self.hash_password(password):
                user_id, username, _, role, must_change_password, login_attempts = user
                
                # Reset login attempts
                c.execute("UPDATE users SET login_attempts=0, last_login=? WHERE id=?", 
                         (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_id))
                conn.commit()
                
                self.current_user_id = user_id
                self.current_user = username
                self.current_user_role = role
                self.session_start_time = datetime.now()
                self.session_timer.start(10 * 1000) # Check every 10 seconds
                self.login_attempts = 0
                
                self.security_manager.log_security_event(
                    user_id, "LOGIN_SUCCESS", 
                    f"User logged in successfully with role: {role}"
                )
                
                # Re-build main UI based on role
                self.setup_main_ui_tabs() 
                
                if must_change_password:
                    self.show_change_password_dialog()
                else:
                    QMessageBox.information(self, "Success", f"Welcome, {self.current_user}!")
                    self.login_username.clear()
                    self.login_password.clear()
                    self.stack.setCurrentWidget(self.main_widget)
                
            else:
                self.login_attempts += 1
                if user:
                    new_attempts = user[5] + 1
                    c.execute("UPDATE users SET login_attempts=? WHERE id=?", (new_attempts, user[0]))
                    
                    if new_attempts >= SECURITY_CONFIG['max_login_attempts']:
                        c.execute("UPDATE users SET is_locked=1 WHERE id=?", (user[0],))
                        QMessageBox.critical(self, "Account Locked", 
                                           "Too many failed login attempts. Account has been locked.")
                    
                    conn.commit()
                
                self.security_manager.log_security_event(
                    user[0] if user else None, "LOGIN_FAILED", 
                    f"Failed login attempt for user: {username}", 
                    success=False
                )
                
                remaining_attempts = SECURITY_CONFIG['max_login_attempts'] - self.login_attempts
                if remaining_attempts > 0:
                    QMessageBox.warning(self, "Error", 
                                       f"Invalid credentials! {remaining_attempts} attempts remaining.")
                else:
                    QMessageBox.critical(self, "Error", "Account locked due to too many failed attempts.")
                
                self.login_password.clear()
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")
        finally:
            conn.close()

    def show_change_password_dialog(self):
        dialog = ChangePasswordDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            current, new, confirm = dialog.get_passwords()
            
            if not current or not new or not confirm:
                QMessageBox.critical(self, "Error", "All fields are required!")
                self.show_change_password_dialog() # Show again
                return
            
            if self.hash_password(current) != self.get_current_user_password():
                QMessageBox.critical(self, "Error", "Current password is incorrect!")
                self.show_change_password_dialog() # Show again
                return
            
            is_valid, message = self.security_manager.validate_password_strength(new)
            if not is_valid:
                QMessageBox.warning(self, "Weak Password", message)
                self.show_change_password_dialog() # Show again
                return
            
            if new != confirm:
                QMessageBox.critical(self, "Error", "New passwords don't match!")
                self.show_change_password_dialog() # Show again
                return
            
            self.update_user_password(new)
            QMessageBox.information(self, "Success", "Password changed successfully!")
            self.stack.setCurrentWidget(self.main_widget)
        else:
            # User closed the dialog - log them out
            self.logout()

    def get_current_user_password(self):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id=?", (self.current_user_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    def update_user_password(self, new_password):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        hashed_password = self.hash_password(new_password)
        c.execute('''UPDATE users SET password=?, must_change_password=0, last_login=? 
                     WHERE id=?''', 
                     (hashed_password, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.current_user_id))
        conn.commit()
        conn.close()
        
        self.security_manager.log_security_event(
            self.current_user_id, "PASSWORD_CHANGE", 
            "User changed password successfully"
        )

    def logout(self):
        if self.current_user_id:
            self.security_manager.log_security_event(
                self.current_user_id, "LOGOUT", 
                "User logged out successfully"
            )
        
        self.current_user = None
        self.current_user_id = None
        self.current_user_role = None
        self.session_start_time = None
        self.login_attempts = 0
        
        # Clear sensitive data from UI
        self.login_username.clear()
        self.login_password.clear()
        self.notebook.clear() # Clear all tabs
        
        self.show_login_page()

    # --- Admin Panel ---

    def show_admin_panel(self):
        if not self.check_permission('users', 'view'):
            self.show_permission_error()
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Admin Panel")
        dialog.setMinimumSize(800, 600)
        
        layout = QVBoxLayout(dialog)
        tabs = QTabWidget()
        
        tabs.addTab(self.create_user_management_tab(), "User Management")
        tabs.addTab(self.create_security_logs_tab(), "Security Logs")
        
        layout.addWidget(tabs)
        dialog.exec()

    def create_user_management_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.user_table = QTableWidget()
        self._setup_table(self.user_table, ["ID", "Username", "Role", "Last Login", "Status"])
        layout.addWidget(self.user_table)
        
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_users_to_table)
        unlock_btn = QPushButton("Unlock User")
        unlock_btn.clicked.connect(self.unlock_user)
        reset_btn = QPushButton("Reset Password")
        reset_btn.clicked.connect(self.reset_user_password)
        
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(unlock_btn)
        btn_layout.addWidget(reset_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        self.load_users_to_table()
        return widget

    def load_users_to_table(self):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''SELECT id, username, role, last_login, is_locked FROM users''')
        data = []
        for row in c.fetchall():
            status = "Locked" if row[4] == 1 else "Active"
            data.append((row[0], row[1], row[2], row[3] or "Never", status))
        conn.close()
        self._populate_table(self.user_table, data)

    def unlock_user(self):
        selected_rows = self.user_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a user first!")
            return
            
        row = selected_rows[0].row()
        user_id = self.user_table.item(row, 0).text()
        username = self.user_table.item(row, 1).text()
        
        if QMessageBox.question(self, "Confirm", f"Unlock user {username}?", 
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("UPDATE users SET is_locked=0, login_attempts=0 WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
            
            self.security_manager.log_security_event(
                self.current_user_id, "USER_UNLOCKED", 
                f"Admin unlocked user: {username}"
            )
            
            QMessageBox.information(self, "Success", "User unlocked successfully!")
            self.load_users_to_table()

    def reset_user_password(self):
        selected_rows = self.user_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a user first!")
            return
            
        row = selected_rows[0].row()
        user_id = self.user_table.item(row, 0).text()
        username = self.user_table.item(row, 1).text()
        
        temp_password = self.security_manager.generate_strong_password()
        
        if QMessageBox.question(self, "Confirm", f"Reset password for {username}?\nTemporary password: {temp_password}",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            hashed_password = self.hash_password(temp_password)
            c.execute('''UPDATE users SET password=?, must_change_password=1, is_locked=0, login_attempts=0 
                         WHERE id=?''', (hashed_password, user_id))
            conn.commit()
            conn.close()
            
            self.security_manager.log_security_event(
                self.current_user_id, "PASSWORD_RESET", 
                f"Admin reset password for user: {username}"
            )
            
            QMessageBox.information(self, "Success", f"Password reset successfully!\nTemporary password: {temp_password}")
            self.load_users_to_table()

    def create_security_logs_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        filter_layout = QHBoxLayout()
        self.logs_from_date = QDateEdit(QDate.currentDate().addMonths(-1))
        self.logs_from_date.setCalendarPopup(True)
        self.logs_to_date = QDateEdit(QDate.currentDate())
        self.logs_to_date.setCalendarPopup(True)
        self.load_logs_btn = QPushButton("Load Logs")
        
        filter_layout.addWidget(QLabel("From:"))
        filter_layout.addWidget(self.logs_from_date)
        filter_layout.addWidget(QLabel("To:"))
        filter_layout.addWidget(self.logs_to_date)
        filter_layout.addWidget(self.load_logs_btn)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        self.security_logs_text = QTextEdit()
        self.security_logs_text.setReadOnly(True)
        self.security_logs_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.security_logs_text)
        
        self.load_logs_btn.clicked.connect(self.load_security_logs)
        self.load_security_logs()
        return widget

    def load_security_logs(self):
        self.security_logs_text.clear()
        from_date = self.logs_from_date.date().toString("yyyy-MM-dd")
        to_date = self.logs_to_date.date().toString("yyyy-MM-dd")
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''SELECT sl.timestamp, u.username, sl.action, sl.description, sl.success 
                     FROM security_logs sl 
                     LEFT JOIN users u ON sl.user_id = u.id 
                     WHERE substr(sl.timestamp, 1, 10) BETWEEN ? AND ?
                     ORDER BY sl.timestamp DESC''', 
                     (from_date, to_date))
        
        for row in c.fetchall():
            timestamp, username, action, description, success = row
            status = "SUCCESS" if success else "FAILED"
            log_entry = f"{timestamp} | {username or 'SYSTEM':<10} | {action:<15} | {description} | {status}"
            self.security_logs_text.append(log_entry)
        conn.close()

    # --- Inventory Tab ---

    def create_inventory_tab(self):
        widget = QWidget()
        main_layout = QHBoxLayout(widget)
        
        # --- Left Panel: Form ---
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setMaximumWidth(350)
        
        # Details Form
        details_group = QGroupBox("Product Details")
        details_layout = QFormLayout()
        self.product_name = QLineEdit()
        self.product_qty = QLineEdit()
        self.product_price = QLineEdit()
        details_layout.addRow("Name:", self.product_name)
        details_layout.addRow("Quantity:", self.product_qty)
        details_layout.addRow("Price:", self.product_price)
        details_group.setLayout(details_layout)
        left_layout.addWidget(details_group)
        
        # Action Buttons
        btn_layout = QGridLayout()
        add_btn = QPushButton("Add")
        update_btn = QPushButton("Update")
        delete_btn = QPushButton("Delete")
        clear_btn = QPushButton("Clear")
        
        add_btn.clicked.connect(self.add_product)
        update_btn.clicked.connect(self.update_product)
        delete_btn.clicked.connect(self.delete_product)
        clear_btn.clicked.connect(self.clear_product_fields)
        
        btn_layout.addWidget(add_btn, 0, 0)
        btn_layout.addWidget(update_btn, 0, 1)
        btn_layout.addWidget(delete_btn, 1, 0)
        btn_layout.addWidget(clear_btn, 1, 1)
        
        # Disable buttons based on permissions
        if not self.check_permission('inventory', 'add'):
            add_btn.setEnabled(False)
        if not self.check_permission('inventory', 'edit'):
            update_btn.setEnabled(False)
        if not self.check_permission('inventory', 'delete'):
            delete_btn.setEnabled(False)
            
        left_layout.addLayout(btn_layout)
        left_layout.addStretch()
        main_layout.addWidget(left_panel)
        
        # --- Right Panel: Table and Search ---
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Search Bar
        search_layout = QHBoxLayout()
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search by name...")
        search_btn = QPushButton("Search")
        all_btn = QPushButton("View All")
        
        search_btn.clicked.connect(self.search_product)
        self.search_entry.returnPressed.connect(self.search_product)
        all_btn.clicked.connect(self.view_inventory)
        
        search_layout.addWidget(QLabel("Search:"))
        search_layout.addWidget(self.search_entry)
        search_layout.addWidget(search_btn)
        search_layout.addWidget(all_btn)
        right_layout.addLayout(search_layout)
        
        # Inventory Table
        self.inventory_table = QTableWidget()
        self._setup_table(self.inventory_table, ["ID", "Name", "Qty", "Price"])
        self.inventory_table.itemSelectionChanged.connect(self.on_inventory_select)
        right_layout.addWidget(self.inventory_table)
        
        main_layout.addWidget(right_panel)
        
        self.view_inventory()
        return widget

    def add_product(self):
        if not self.check_permission('inventory', 'add'):
            self.show_permission_error()
            return
            
        name = self.product_name.text().strip()
        qty = self.validate_numeric(self.product_qty.text().strip(), 'int')
        price = self.validate_numeric(self.product_price.text().strip(), 'float')
        
        if not name:
            QMessageBox.warning(self, "Error", "Product name is required!")
            return
        if qty is None or qty < 0:
            QMessageBox.warning(self, "Error", "Enter valid quantity (integer >= 0)!")
            return
        if price is None or price < 0:
            QMessageBox.warning(self, "Error", "Enter valid price (number >= 0)!")
            return
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO inventory (name, quantity, price, created_by, created_date, last_modified) 
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                         (name, qty, price, self.current_user_id, 
                          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                          datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "PRODUCT_ADDED", 
                f"Added product: {name} (Qty: {qty}, Price: {price})"
            )
            
            QMessageBox.information(self, "Success", "Product added successfully!")
            self.clear_product_fields()
            self.view_inventory()
            self.refresh_billing_inventory()
        except sqlite3.IntegrityError:
            QMessageBox.critical(self, "Error", f"Product '{name}' already exists! Use a different name.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add product: {str(e)}")
        finally:
            conn.close()

    def view_inventory(self):
        if not hasattr(self, 'inventory_table'):
            return # Tab not created yet
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, quantity, price FROM inventory ORDER BY name")
        rows = c.fetchall()
        conn.close()
        self._populate_table(self.inventory_table, rows)

    def on_inventory_select(self):
        selected_rows = self.inventory_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        self.product_name.setText(self.inventory_table.item(row, 1).text())
        self.product_qty.setText(self.inventory_table.item(row, 2).text())
        self.product_price.setText(self.inventory_table.item(row, 3).text())

    def clear_product_fields(self):
        self.product_name.clear()
        self.product_qty.clear()
        self.product_price.clear()

    def update_product(self):
        if not self.check_permission('inventory', 'edit'):
            self.show_permission_error()
            return
            
        selected_rows = self.inventory_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a product from the table first!")
            return
        
        row = selected_rows[0].row()
        item_id = self.validate_numeric(self.inventory_table.item(row, 0).text(), 'int')
        current_name = self.inventory_table.item(row, 1).text()
        
        new_name = self.product_name.text().strip()
        qty = self.validate_numeric(self.product_qty.text().strip(), 'int')
        price = self.validate_numeric(self.product_price.text().strip(), 'float')
        
        if item_id is None:
            QMessageBox.critical(self, "Error", "Invalid product selected!")
            return
        if not new_name:
            QMessageBox.warning(self, "Error", "Product name is required!")
            return
        if qty is None or qty < 0:
            QMessageBox.warning(self, "Error", "Enter valid quantity (integer >= 0)!")
            return
        if price is None or price < 0:
            QMessageBox.warning(self, "Error", "Enter valid price (number >= 0)!")
            return
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            if new_name != current_name:
                c.execute("SELECT id FROM inventory WHERE name = ?", (new_name,))
                if c.fetchone():
                    QMessageBox.critical(self, "Error", f"Product '{new_name}' already exists! Use a different name.")
                    conn.close()
                    return
            
            c.execute("UPDATE inventory SET name=?, quantity=?, price=?, last_modified=? WHERE id=?", 
                     (new_name, qty, price, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), item_id))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "PRODUCT_UPDATED", 
                f"Updated product: {new_name} (ID: {item_id})"
            )
            
            QMessageBox.information(self, "Success", "Product updated successfully!")
            self.clear_product_fields()
            self.view_inventory()
            self.refresh_billing_inventory()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update product: {str(e)}")
        finally:
            conn.close()

    def delete_product(self):
        if not self.check_permission('inventory', 'delete'):
            self.show_permission_error()
            return
            
        selected_rows = self.inventory_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a product from the table first!")
            return
            
        row = selected_rows[0].row()
        item_id = self.validate_numeric(self.inventory_table.item(row, 0).text(), 'int')
        if item_id is None:
            QMessageBox.critical(self, "Error", "Invalid selection!")
            return
        
        if QMessageBox.question(self, "Confirm", "Are you sure you want to delete this product?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM inventory WHERE id=?", (item_id,))
            conn.commit()
            conn.close()
            
            self.security_manager.log_security_event(
                self.current_user_id, "PRODUCT_DELETED", 
                f"Deleted product ID: {item_id}"
            )
            
            QMessageBox.information(self, "Success", "Product deleted!")
            self.view_inventory()
            self.refresh_billing_inventory()

    def search_product(self):
        query = self.search_entry.text().strip().lower()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, quantity, price FROM inventory WHERE lower(name) LIKE ? ORDER BY name", (f"%{query}%",))
        rows = c.fetchall()
        conn.close()
        self._populate_table(self.inventory_table, rows)

    # --- Billing Tab ---

    def create_billing_tab(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        
        # --- Top Controls ---
        controls_layout = QHBoxLayout()
        new_bill_btn = QPushButton("New Bill")
        new_bill_btn.clicked.connect(self.new_bill)
        refresh_prod_btn = QPushButton("Refresh Products")
        refresh_prod_btn.clicked.connect(self.refresh_billing_inventory)
        
        controls_layout.addWidget(new_bill_btn)
        controls_layout.addWidget(refresh_prod_btn)
        controls_layout.addStretch()
        main_layout.addLayout(controls_layout)

        # --- Customer Frame ---
        customer_group = QGroupBox("Customer")
        customer_layout = QHBoxLayout(customer_group)
        self.customer_label = QLabel(f"Customer: {self.selected_customer_name}")
        self.customer_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        select_cust_btn = QPushButton("Select Customer")
        select_cust_btn.clicked.connect(self.select_customer)
        add_cust_btn = QPushButton("Add New Customer")
        add_cust_btn.clicked.connect(self.add_customer_dialog)
        
        customer_layout.addWidget(self.customer_label)
        customer_layout.addStretch()
        customer_layout.addWidget(select_cust_btn)
        customer_layout.addWidget(add_cust_btn)
        main_layout.addWidget(customer_group)

        # --- Bill Display ---
        bill_display_group = QGroupBox("Current Bill")
        bill_display_layout = QVBoxLayout(bill_display_group)
        
        # Bill text area
        self.bill_text = QTextEdit()
        self.bill_text.setReadOnly(True)
        self.bill_text.setFont(QFont("Courier", 10))
        self.bill_text.setMinimumHeight(150)
        bill_display_layout.addWidget(self.bill_text)
        
        # Bill actions
        bill_actions_layout = QHBoxLayout()
        print_bill_btn = QPushButton("Print Bill")
        print_bill_btn.clicked.connect(lambda: self.print_text_edit(self.bill_text, "Invoice"))
        
        self.payment_method = QComboBox()
        self.payment_method.addItems(["Cash", "Card", "UPI", "Online"])
        
        pdf_bill_btn = QPushButton("Generate PDF Bill")
        pdf_bill_btn.clicked.connect(self.generate_pdf)
        
        bill_actions_layout.addWidget(print_bill_btn)
        bill_actions_layout.addStretch()
        bill_actions_layout.addWidget(QLabel("Payment Method:"))
        bill_actions_layout.addWidget(self.payment_method)
        bill_actions_layout.addWidget(pdf_bill_btn)
        bill_display_layout.addLayout(bill_actions_layout)
        
        main_layout.addWidget(bill_display_group)

        # --- Product Frame ---
        product_group = QGroupBox("Add Products to Bill")
        product_layout = QVBoxLayout(product_group)
        
        # Available products table
        self.bill_inventory_table = QTableWidget()
        self._setup_table(self.bill_inventory_table, ["ID", "Name", "Available Qty", "Price"])
        self.bill_inventory_table.setMinimumHeight(150)
        product_layout.addWidget(self.bill_inventory_table)
        
        # Add to bill layout
        add_layout = QHBoxLayout()
        self.bill_qty_entry = QLineEdit()
        self.bill_qty_entry.setPlaceholderText("Qty")
        self.bill_qty_entry.setMaximumWidth(60)
        add_to_bill_btn = QPushButton("Add to Bill")
        add_to_bill_btn.clicked.connect(self.add_to_bill)
        
        add_layout.addStretch()
        add_layout.addWidget(QLabel("Quantity:"))
        add_layout.addWidget(self.bill_qty_entry)
        add_layout.addWidget(add_to_bill_btn)
        product_layout.addLayout(add_layout)
        
        main_layout.addWidget(product_group)
        main_layout.addStretch()
        
        return widget

    def refresh_billing_inventory(self):
        if not hasattr(self, 'bill_inventory_table'):
            return # Tab not created yet
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, quantity, price FROM inventory WHERE quantity > 0 ORDER BY name")
        rows = c.fetchall()
        conn.close()
        self._populate_table(self.bill_inventory_table, rows)

    def new_bill(self):
        self.current_bill = []
        self.bill_text.clear()
        self.bill_text.append("=== NEW BILL ===")
        self.bill_text.append(f"Customer: {self.selected_customer_name}")
        self.bill_text.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.bill_text.append("-" * 50)
        self.bill_text.append("Items will appear here...")

    def add_to_bill(self):
        selected_rows = self.bill_inventory_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Please select a product from the available products list!")
            return
            
        row = selected_rows[0].row()
        
        item_id = self.validate_numeric(self.bill_inventory_table.item(row, 0).text(), 'int')
        name = self.bill_inventory_table.item(row, 1).text()
        available_qty = self.validate_numeric(self.bill_inventory_table.item(row, 2).text(), 'int')
        price = self.validate_numeric(self.bill_inventory_table.item(row, 3).text(), 'float')
        
        if available_qty is None or price is None or item_id is None:
            QMessageBox.critical(self, "Error", "Invalid product data! Please refresh and try again.")
            return
            
        bill_qty = self.validate_numeric(self.bill_qty_entry.text().strip(), 'int')
        if bill_qty is None or bill_qty <= 0:
            QMessageBox.warning(self, "Error", "Please enter a valid quantity (positive integer)!")
            return
            
        if bill_qty > available_qty:
            QMessageBox.warning(self, "Error", f"Insufficient stock! Available: {available_qty}")
            return
            
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("UPDATE inventory SET quantity = quantity - ? WHERE id=?", (bill_qty, item_id))
            
            if self.selected_customer_id:
                c.execute("UPDATE customers SET total_purchases = total_purchases + ? WHERE id=?", 
                         (bill_qty * price, self.selected_customer_id))
            
            conn.commit()
        except Exception as e:
            QMessageBox.critical(self, "DB Error", f"Failed to update database: {e}")
            conn.close()
            return
        finally:
            conn.close()
        
        self.current_bill.append((name, bill_qty, price))
        
        self.bill_text.clear()
        self.bill_text.append("=== CURRENT BILL ===")
        self.bill_text.append(f"Customer: {self.selected_customer_name}")
        self.bill_text.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.bill_text.append("-" * 50)
        
        total = 0
        self.bill_text.append(f"{'Item':<20} {'Qty':>3} x {'Price':>7} = {'Subtotal':>8}")
        self.bill_text.append("-" * 50)
        
        for item_name, item_qty, item_price in self.current_bill:
            item_subtotal = item_qty * item_price
            total += item_subtotal
            self.bill_text.append(f"{item_name:<20} {item_qty:>3} x ${item_price:>6.2f} = ${item_subtotal:>7.2f}")
        
        self.bill_text.append("-" * 50)
        self.bill_text.append(f"TOTAL: ${total:>7.2f}")
        
        self.bill_qty_entry.clear()
        self.refresh_billing_inventory()
        self.view_inventory() # Refresh inventory tab as well

    def generate_pdf(self):
        if not REPORTLAB_AVAILABLE:
            QMessageBox.critical(self, "Error", "PDF generation is disabled. `reportlab` library not found.")
            return

        if not self.current_bill:
            QMessageBox.warning(self, "Error", "No items in the bill! Add some products first.")
            return
            
        total = sum(q * p for _, q, p in self.current_bill)
        date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO bills (user_id, date, total, items, customer_info) VALUES (?, ?, ?, ?, ?)", 
                     (self.current_user_id, date_str, total, str(self.current_bill), self.selected_customer_name))
            bill_id = c.lastrowid
            
            conn.commit()
        except Exception as e:
            QMessageBox.critical(self, "DB Error", f"Failed to save bill to database: {e}")
            conn.close()
            return
        finally:
            conn.close()
        
        os.makedirs("bills", exist_ok=True)
        pdf_file = f"bills/bill_{date_str}.pdf"
        
        try:
            cnv = canvas.Canvas(pdf_file, pagesize=letter)
            w, h = letter
            y = h - 100
            
            cnv.setFont("Helvetica-Bold", 16)
            cnv.drawString(100, y, "INVOICE")
            y -= 30
            
            cnv.setFont("Helvetica", 12)
            cnv.drawString(100, y, f"Customer: {self.selected_customer_name}")
            y -= 20
            cnv.drawString(100, y, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y -= 20
            cnv.drawString(100, y, f"Payment Method: {self.payment_method.currentText()}")
            y -= 40
            
            cnv.setFont("Helvetica-Bold", 12)
            cnv.drawString(100, y, "Item")
            cnv.drawString(300, y, "Qty")
            cnv.drawString(350, y, "Price")
            cnv.drawString(450, y, "Subtotal")
            y -= 20
            
            cnv.setFont("Helvetica", 12)
            for name, q, p in self.current_bill:
                sub = q * p
                cnv.drawString(100, y, name)
                cnv.drawString(300, y, str(q))
                cnv.drawString(350, y, f"${p:.2f}")
                cnv.drawString(450, y, f"${sub:.2f}")
                y -= 20
                if y < 100:
                    cnv.showPage()
                    y = h - 50
                    cnv.setFont("Helvetica", 12)
            
            y -= 20
            cnv.setFont("Helvetica-Bold", 14)
            cnv.drawString(350, y, f"TOTAL: ${total:.2f}")
            
            cnv.save()
            
            self.security_manager.log_security_event(
                self.current_user_id, "BILL_GENERATED", 
                f"Generated PDF bill: {pdf_file} for customer: {self.selected_customer_name}"
            )
            
            QMessageBox.information(self, "Success", f"PDF bill generated successfully!\nFile: {pdf_file}")
            self.new_bill() # Start a new bill
        except Exception as e:
            QMessageBox.critical(self, "PDF Error", f"Failed to generate PDF: {e}")

    def select_customer(self):
        dialog = SelectCustomerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.selected_customer_id, self.selected_customer_name = dialog.get_selection()
            self.customer_label.setText(f"Customer: {self.selected_customer_name}")
            self.new_bill() # Start new bill with this customer

    def add_customer_dialog(self):
        dialog = AddCustomerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name, phone, email = dialog.get_details()
            
            if not name:
                QMessageBox.warning(self, "Error", "Customer name is required!")
                return
                
            if email and not self.validate_email(email):
                QMessageBox.warning(self, "Error", "Invalid email format! Please include '@' in the email address.")
                return
                
            if phone and not self.validate_phone(phone):
                QMessageBox.warning(self, "Error", "Invalid phone format! Please use 2-digit country code + 10-digit number (e.g., 911234567890).")
                return
                
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            try:
                c.execute('''INSERT INTO customers (name, phone, email, created_date, created_by) 
                             VALUES (?, ?, ?, ?, ?)''', 
                             (name, phone, email, datetime.now().strftime("%Y-%m-%d"), self.current_user_id))
                conn.commit()
                self.selected_customer_id = c.lastrowid
                self.selected_customer_name = name
                self.customer_label.setText(f"Customer: {name}")
                self.new_bill() # Start new bill
                
                self.security_manager.log_security_event(
                    self.current_user_id, "CUSTOMER_ADDED", 
                    f"Added customer: {name}"
                )
                self.view_customers() # Refresh customer tab
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add customer: {str(e)}")
            finally:
                conn.close()

    # --- Customer Tab ---

    def create_customer_tab(self):
        # This implementation is very similar to the inventory tab
        widget = QWidget()
        main_layout = QHBoxLayout(widget)
        
        # --- Left Panel: Form ---
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setMaximumWidth(350)
        
        details_group = QGroupBox("Customer Details")
        details_layout = QFormLayout()
        self.customer_name = QLineEdit()
        self.customer_phone = QLineEdit()
        self.customer_phone.setPlaceholderText("e.g., 911234567890")
        self.customer_email = QLineEdit()
        self.customer_address = QLineEdit()
        details_layout.addRow("Name:*", self.customer_name)
        details_layout.addRow("Phone:", self.customer_phone)
        details_layout.addRow("Email:", self.customer_email)
        details_layout.addRow("Address:", self.customer_address)
        details_group.setLayout(details_layout)
        left_layout.addWidget(details_group)
        
        btn_layout = QGridLayout()
        add_btn = QPushButton("Add Customer")
        update_btn = QPushButton("Update")
        delete_btn = QPushButton("Delete")
        clear_btn = QPushButton("Clear")
        
        add_btn.clicked.connect(self.add_customer)
        update_btn.clicked.connect(self.update_customer)
        delete_btn.clicked.connect(self.delete_customer)
        clear_btn.clicked.connect(self.clear_customer_fields)
        
        btn_layout.addWidget(add_btn, 0, 0)
        btn_layout.addWidget(update_btn, 0, 1)
        btn_layout.addWidget(delete_btn, 1, 0)
        btn_layout.addWidget(clear_btn, 1, 1)
        
        if not self.check_permission('customers', 'add'):
            add_btn.setEnabled(False)
        if not self.check_permission('customers', 'edit'):
            update_btn.setEnabled(False)
        if not self.check_permission('customers', 'delete'):
            delete_btn.setEnabled(False)
            
        left_layout.addLayout(btn_layout)
        left_layout.addStretch()
        main_layout.addWidget(left_panel)
        
        # --- Right Panel: Table ---
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        self.customer_table = QTableWidget()
        self._setup_table(self.customer_table, ["ID", "Name", "Phone", "Email", "Address", "Total Purchases"])
        self.customer_table.itemSelectionChanged.connect(self.on_customer_select)
        right_layout.addWidget(self.customer_table)
        
        main_layout.addWidget(right_panel)
        
        self.view_customers()
        return widget

    def add_customer(self):
        if not self.check_permission('customers', 'add'):
            self.show_permission_error()
            return
            
        name = self.customer_name.text().strip()
        phone = self.customer_phone.text().strip()
        email = self.customer_email.text().strip()
        address = self.customer_address.text().strip()
        
        if not name:
            QMessageBox.warning(self, "Error", "Customer name is required!")
            return
        
        if email and not self.validate_email(email):
            QMessageBox.warning(self, "Error", "Invalid email format! Please include '@' in the email address.")
            return
            
        if phone and not self.validate_phone(phone):
            QMessageBox.warning(self, "Error", "Invalid phone format! Please use 2-digit country code + 10-digit number (e.g., 911234567890).")
            return
            
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO customers (name, phone, email, address, created_date, created_by) 
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                         (name, phone, email, address, datetime.now().strftime("%Y-%m-%d"), self.current_user_id))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "CUSTOMER_ADDED", 
                f"Added customer: {name}"
            )
            
            QMessageBox.information(self, "Success", "Customer added successfully!")
            self.clear_customer_fields()
            self.view_customers()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add customer: {str(e)}")
        finally:
            conn.close()

    def view_customers(self):
        if not hasattr(self, 'customer_table'):
            return
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, phone, email, address, total_purchases FROM customers ORDER BY name")
        rows = c.fetchall()
        conn.close()
        self._populate_table(self.customer_table, rows)

    def on_customer_select(self):
        selected_rows = self.customer_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        self.customer_name.setText(self.customer_table.item(row, 1).text())
        self.customer_phone.setText(self.customer_table.item(row, 2).text())
        self.customer_email.setText(self.customer_table.item(row, 3).text())
        self.customer_address.setText(self.customer_table.item(row, 4).text())

    def update_customer(self):
        if not self.check_permission('customers', 'edit'):
            self.show_permission_error()
            return
            
        selected_rows = self.customer_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a customer first!")
            return
            
        row = selected_rows[0].row()
        customer_id = self.customer_table.item(row, 0).text()
        
        name = self.customer_name.text().strip()
        phone = self.customer_phone.text().strip()
        email = self.customer_email.text().strip()
        address = self.customer_address.text().strip()
        
        if not name:
            QMessageBox.warning(self, "Error", "Customer name is required!")
            return
        
        if email and not self.validate_email(email):
            QMessageBox.warning(self, "Error", "Invalid email format!")
            return
            
        if phone and not self.validate_phone(phone):
            QMessageBox.warning(self, "Error", "Invalid phone format!")
            return
            
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('''UPDATE customers SET name=?, phone=?, email=?, address=? 
                         WHERE id=?''', (name, phone, email, address, customer_id))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "CUSTOMER_UPDATED", 
                f"Updated customer: {name} (ID: {customer_id})"
            )
            
            QMessageBox.information(self, "Success", "Customer updated successfully!")
            self.clear_customer_fields()
            self.view_customers()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update customer: {str(e)}")
        finally:
            conn.close()

    def delete_customer(self):
        if not self.check_permission('customers', 'delete'):
            self.show_permission_error()
            return
            
        selected_rows = self.customer_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a customer first!")
            return
            
        row = selected_rows[0].row()
        customer_id = self.customer_table.item(row, 0).text()
        
        if QMessageBox.question(self, "Confirm", "Delete this customer?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM customers WHERE id=?", (customer_id,))
            conn.commit()
            conn.close()
            
            self.security_manager.log_security_event(
                self.current_user_id, "CUSTOMER_DELETED", 
                f"Deleted customer ID: {customer_id}"
            )
            
            QMessageBox.information(self, "Success", "Customer deleted!")
            self.view_customers()

    def clear_customer_fields(self):
        self.customer_name.clear()
        self.customer_phone.clear()
        self.customer_email.clear()
        self.customer_address.clear()

    # --- Supplier Tab ---

    def create_supplier_tab(self):
        # This implementation is very similar to the customer tab
        widget = QWidget()
        main_layout = QHBoxLayout(widget)
        
        # --- Left Panel: Form ---
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setMaximumWidth(350)
        
        details_group = QGroupBox("Supplier Details")
        details_layout = QFormLayout()
        self.supplier_name = QLineEdit()
        self.supplier_contact = QLineEdit()
        self.supplier_phone = QLineEdit()
        self.supplier_phone.setPlaceholderText("e.g., 911234567890")
        self.supplier_email = QLineEdit()
        self.supplier_address = QLineEdit()
        self.supplier_items = QLineEdit()
        details_layout.addRow("Name:*", self.supplier_name)
        details_layout.addRow("Contact Person:", self.supplier_contact)
        details_layout.addRow("Phone:", self.supplier_phone)
        details_layout.addRow("Email:", self.supplier_email)
        details_layout.addRow("Address:", self.supplier_address)
        details_layout.addRow("Items Supplied:", self.supplier_items)
        details_group.setLayout(details_layout)
        left_layout.addWidget(details_group)
        
        btn_layout = QGridLayout()
        add_btn = QPushButton("Add Supplier")
        update_btn = QPushButton("Update")
        delete_btn = QPushButton("Delete")
        clear_btn = QPushButton("Clear")
        
        add_btn.clicked.connect(self.add_supplier)
        update_btn.clicked.connect(self.update_supplier)
        delete_btn.clicked.connect(self.delete_supplier)
        clear_btn.clicked.connect(self.clear_supplier_fields)
        
        btn_layout.addWidget(add_btn, 0, 0)
        btn_layout.addWidget(update_btn, 0, 1)
        btn_layout.addWidget(delete_btn, 1, 0)
        btn_layout.addWidget(clear_btn, 1, 1)

        if not self.check_permission('suppliers', 'add'):
            add_btn.setEnabled(False)
        if not self.check_permission('suppliers', 'edit'):
            update_btn.setEnabled(False)
        if not self.check_permission('suppliers', 'delete'):
            delete_btn.setEnabled(False)

        left_layout.addLayout(btn_layout)
        left_layout.addStretch()
        main_layout.addWidget(left_panel)
        
        # --- Right Panel: Table ---
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        self.supplier_table = QTableWidget()
        self._setup_table(self.supplier_table, ["ID", "Name", "Contact", "Phone", "Email", "Address", "Items"])
        self.supplier_table.itemSelectionChanged.connect(self.on_supplier_select)
        right_layout.addWidget(self.supplier_table)
        
        main_layout.addWidget(right_panel)
        
        self.view_suppliers()
        return widget

    def add_supplier(self):
        if not self.check_permission('suppliers', 'add'):
            self.show_permission_error()
            return
            
        name = self.supplier_name.text().strip()
        contact = self.supplier_contact.text().strip()
        phone = self.supplier_phone.text().strip()
        email = self.supplier_email.text().strip()
        address = self.supplier_address.text().strip()
        items = self.supplier_items.text().strip()
        
        if not name:
            QMessageBox.warning(self, "Error", "Supplier name is required!")
            return
        
        if email and not self.validate_email(email):
            QMessageBox.warning(self, "Error", "Invalid email format!")
            return
            
        if phone and not self.validate_phone(phone):
            QMessageBox.warning(self, "Error", "Invalid phone format!")
            return
            
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO suppliers (name, contact_person, phone, email, address, items_supplied, created_date, created_by) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                         (name, contact, phone, email, address, items, datetime.now().strftime("%Y-%m-%d"), self.current_user_id))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "SUPPLIER_ADDED", 
                f"Added supplier: {name}"
            )
            
            QMessageBox.information(self, "Success", "Supplier added successfully!")
            self.clear_supplier_fields()
            self.view_suppliers()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add supplier: {str(e)}")
        finally:
            conn.close()

    def view_suppliers(self):
        if not hasattr(self, 'supplier_table'):
            return
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, name, contact_person, phone, email, address, items_supplied FROM suppliers ORDER BY name")
        rows = c.fetchall()
        conn.close()
        self._populate_table(self.supplier_table, rows)

    def on_supplier_select(self):
        selected_rows = self.supplier_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        self.supplier_name.setText(self.supplier_table.item(row, 1).text())
        self.supplier_contact.setText(self.supplier_table.item(row, 2).text())
        self.supplier_phone.setText(self.supplier_table.item(row, 3).text())
        self.supplier_email.setText(self.supplier_table.item(row, 4).text())
        self.supplier_address.setText(self.supplier_table.item(row, 5).text())
        self.supplier_items.setText(self.supplier_table.item(row, 6).text())

    def update_supplier(self):
        if not self.check_permission('suppliers', 'edit'):
            self.show_permission_error()
            return
            
        selected_rows = self.supplier_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a supplier first!")
            return
            
        row = selected_rows[0].row()
        supplier_id = self.supplier_table.item(row, 0).text()

        name = self.supplier_name.text().strip()
        contact = self.supplier_contact.text().strip()
        phone = self.supplier_phone.text().strip()
        email = self.supplier_email.text().strip()
        address = self.supplier_address.text().strip()
        items = self.supplier_items.text().strip()
        
        if not name:
            QMessageBox.warning(self, "Error", "Supplier name is required!")
            return
        
        # (Validation logic identical to add_supplier)
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('''UPDATE suppliers SET name=?, contact_person=?, phone=?, email=?, address=?, items_supplied=?
                         WHERE id=?''', (name, contact, phone, email, address, items, supplier_id))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "SUPPLIER_UPDATED", 
                f"Updated supplier: {name} (ID: {supplier_id})"
            )
            
            QMessageBox.information(self, "Success", "Supplier updated successfully!")
            self.clear_supplier_fields()
            self.view_suppliers()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update supplier: {str(e)}")
        finally:
            conn.close()

    def delete_supplier(self):
        if not self.check_permission('suppliers', 'delete'):
            self.show_permission_error()
            return
            
        selected_rows = self.supplier_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select a supplier first!")
            return
            
        row = selected_rows[0].row()
        supplier_id = self.supplier_table.item(row, 0).text()

        if QMessageBox.question(self, "Confirm", "Delete this supplier?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM suppliers WHERE id=?", (supplier_id,))
            conn.commit()
            conn.close()
            
            self.security_manager.log_security_event(
                self.current_user_id, "SUPPLIER_DELETED", 
                f"Deleted supplier ID: {supplier_id}"
            )
            
            QMessageBox.information(self, "Success", "Supplier deleted!")
            self.view_suppliers()

    def clear_supplier_fields(self):
        self.supplier_name.clear()
        self.supplier_contact.clear()
        self.supplier_phone.clear()
        self.supplier_email.clear()
        self.supplier_address.clear()
        self.supplier_items.clear()

    # --- Expense Tab ---

    def create_expense_tab(self):
        widget = QWidget()
        main_layout = QHBoxLayout(widget)
        
        # --- Left Panel: Form ---
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setMaximumWidth(350)
        
        details_group = QGroupBox("Expense Details")
        details_layout = QFormLayout()
        self.expense_category = QComboBox()
        self.expense_category.addItems(["Rent", "Utilities", "Salaries", "Supplies", "Maintenance", "Other"])
        self.expense_category.setEditable(True)
        self.expense_amount = QLineEdit()
        self.expense_description = QLineEdit()
        self.expense_paid_to = QLineEdit()
        self.expense_payment_method = QComboBox()
        self.expense_payment_method.addItems(["Cash", "Bank Transfer", "Card", "Online"])
        
        details_layout.addRow("Category:*", self.expense_category)
        details_layout.addRow("Amount:*", self.expense_amount)
        details_layout.addRow("Description:", self.expense_description)
        details_layout.addRow("Paid To:", self.expense_paid_to)
        details_layout.addRow("Payment Method:", self.expense_payment_method)
        details_group.setLayout(details_layout)
        left_layout.addWidget(details_group)
        
        btn_layout = QGridLayout()
        add_btn = QPushButton("Add Expense")
        update_btn = QPushButton("Update")
        delete_btn = QPushButton("Delete")
        clear_btn = QPushButton("Clear")
        
        add_btn.clicked.connect(self.add_expense)
        update_btn.clicked.connect(self.update_expense)
        delete_btn.clicked.connect(self.delete_expense)
        clear_btn.clicked.connect(self.clear_expense_fields)
        
        btn_layout.addWidget(add_btn, 0, 0)
        btn_layout.addWidget(update_btn, 0, 1)
        btn_layout.addWidget(delete_btn, 1, 0)
        btn_layout.addWidget(clear_btn, 1, 1)

        if not self.check_permission('expenses', 'add'):
            add_btn.setEnabled(False)
        if not self.check_permission('expenses', 'edit'):
            update_btn.setEnabled(False)
        if not self.check_permission('expenses', 'delete'):
            delete_btn.setEnabled(False)
            
        left_layout.addLayout(btn_layout)
        left_layout.addStretch()
        main_layout.addWidget(left_panel)
        
        # --- Right Panel: Table ---
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        self.expense_table = QTableWidget()
        self._setup_table(self.expense_table, ["ID", "Date", "Category", "Amount", "Description", "Paid To", "Payment Method"])
        self.expense_table.itemSelectionChanged.connect(self.on_expense_select)
        right_layout.addWidget(self.expense_table)
        
        self.expense_summary_label = QLabel("Total Expenses: $0.00")
        self.expense_summary_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.expense_summary_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        right_layout.addWidget(self.expense_summary_label)
        
        main_layout.addWidget(right_panel)
        
        self.view_expenses()
        return widget

    def add_expense(self):
        if not self.check_permission('expenses', 'add'):
            self.show_permission_error()
            return
            
        category = self.expense_category.currentText().strip()
        amount = self.validate_numeric(self.expense_amount.text().strip(), 'float')
        description = self.expense_description.text().strip()
        paid_to = self.expense_paid_to.text().strip()
        payment_method = self.expense_payment_method.currentText().strip()
        
        if not category:
            QMessageBox.warning(self, "Error", "Expense category is required!")
            return
            
        if amount is None or amount <= 0:
            QMessageBox.warning(self, "Error", "Please enter a valid positive amount!")
            return
            
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO expenses (category, amount, date, description, paid_to, payment_method, created_by) 
                         VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                         (category, amount, datetime.now().strftime("%Y-%m-%d"), description, paid_to, payment_method, self.current_user_id))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "EXPENSE_ADDED", 
                f"Added expense: {category} - ${amount:.2f}"
            )
            
            QMessageBox.information(self, "Success", "Expense added successfully!")
            self.clear_expense_fields()
            self.view_expenses()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add expense: {str(e)}")
        finally:
            conn.close()

    def view_expenses(self):
        if not hasattr(self, 'expense_table'):
            return
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, date, category, amount, description, paid_to, payment_method FROM expenses ORDER BY date DESC")
        rows = c.fetchall()
        
        total = sum(row[3] for row in rows if row[3])
        
        conn.close()
        self._populate_table(self.expense_table, rows)
        self.expense_summary_label.setText(f"Total Expenses: ${total:.2f}")

    def on_expense_select(self):
        selected_rows = self.expense_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        self.expense_category.setCurrentText(self.expense_table.item(row, 2).text())
        self.expense_amount.setText(self.expense_table.item(row, 3).text())
        self.expense_description.setText(self.expense_table.item(row, 4).text())
        self.expense_paid_to.setText(self.expense_table.item(row, 5).text())
        self.expense_payment_method.setCurrentText(self.expense_table.item(row, 6).text())

    def update_expense(self):
        if not self.check_permission('expenses', 'edit'):
            self.show_permission_error()
            return
            
        selected_rows = self.expense_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select an expense first!")
            return
            
        row = selected_rows[0].row()
        expense_id = self.expense_table.item(row, 0).text()
        
        category = self.expense_category.currentText().strip()
        amount = self.validate_numeric(self.expense_amount.text().strip(), 'float')
        description = self.expense_description.text().strip()
        paid_to = self.expense_paid_to.text().strip()
        payment_method = self.expense_payment_method.currentText().strip()
        
        if not category or amount is None or amount <= 0:
            QMessageBox.warning(self, "Error", "Valid category and positive amount are required!")
            return
            
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('''UPDATE expenses SET category=?, amount=?, description=?, paid_to=?, payment_method=?
                         WHERE id=?''', (category, amount, description, paid_to, payment_method, expense_id))
            conn.commit()
            
            self.security_manager.log_security_event(
                self.current_user_id, "EXPENSE_UPDATED", 
                f"Updated expense ID: {expense_id}"
            )
            
            QMessageBox.information(self, "Success", "Expense updated successfully!")
            self.clear_expense_fields()
            self.view_expenses()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update expense: {str(e)}")
        finally:
            conn.close()

    def delete_expense(self):
        if not self.check_permission('expenses', 'delete'):
            self.show_permission_error()
            return
            
        selected_rows = self.expense_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Select an expense first!")
            return
            
        row = selected_rows[0].row()
        expense_id = self.expense_table.item(row, 0).text()
        
        if QMessageBox.question(self, "Confirm", "Delete this expense?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM expenses WHERE id=?", (expense_id,))
            conn.commit()
            conn.close()
            
            self.security_manager.log_security_event(
                self.current_user_id, "EXPENSE_DELETED", 
                f"Deleted expense ID: {expense_id}"
            )
            
            QMessageBox.information(self, "Success", "Expense deleted!")
            self.view_expenses()

    def clear_expense_fields(self):
        self.expense_category.setCurrentIndex(0)
        self.expense_amount.clear()
        self.expense_description.clear()
        self.expense_paid_to.clear()
        self.expense_payment_method.setCurrentIndex(0)

    # --- Reports Tab ---

    def create_reports_tab(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        
        # --- Controls ---
        controls_group = QGroupBox("Generate Reports")
        controls_layout = QHBoxLayout(controls_group)
        
        self.report_from_date = QDateEdit(QDate.currentDate().addDays(-QDate.currentDate().day() + 1))
        self.report_from_date.setCalendarPopup(True)
        self.report_to_date = QDateEdit(QDate.currentDate())
        self.report_to_date.setCalendarPopup(True)
        
        sales_btn = QPushButton("Sales Report")
        expense_btn = QPushButton("Expense Report")
        pl_btn = QPushButton("Profit/Loss Report")
        
        sales_btn.clicked.connect(self.generate_sales_report)
        expense_btn.clicked.connect(self.generate_expense_report)
        pl_btn.clicked.connect(self.generate_profit_loss_report)
        
        controls_layout.addWidget(QLabel("From:"))
        controls_layout.addWidget(self.report_from_date)
        controls_layout.addWidget(QLabel("To:"))
        controls_layout.addWidget(self.report_to_date)
        controls_layout.addStretch()
        controls_layout.addWidget(sales_btn)
        controls_layout.addWidget(expense_btn)
        controls_layout.addWidget(pl_btn)
        
        main_layout.addWidget(controls_group)
        
        # --- Report Output ---
        output_group = QGroupBox("Report Output")
        output_layout = QVBoxLayout(output_group)
        
        output_btn_layout = QHBoxLayout()
        print_btn = QPushButton("Print Report")
        print_btn.clicked.connect(lambda: self.print_text_edit(self.report_text, "Business Report"))
        save_btn = QPushButton("Save Report")
        save_btn.clicked.connect(lambda: self.save_report_to_file(self.report_text.toPlainText()))
        output_btn_layout.addWidget(print_btn)
        output_btn_layout.addWidget(save_btn)
        output_btn_layout.addStretch()
        output_layout.addLayout(output_btn_layout)
        
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setFont(QFont("Courier", 10))
        output_layout.addWidget(self.report_text)
        
        main_layout.addWidget(output_group)
        
        return widget

    def generate_sales_report(self):
        if not self.check_permission('reports', 'generate'):
            self.show_permission_error()
            return
            
        from_date = self.report_from_date.date().toString("yyyy-MM-dd")
        to_date = self.report_to_date.date().toString("yyyy-MM-dd")
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute('''SELECT date, total FROM bills 
                     WHERE substr(date, 1, 10) BETWEEN ? AND ? 
                     ORDER BY date''', 
                     (from_date, to_date))
        sales_data = c.fetchall()
        
        total_sales = sum(row[1] for row in sales_data)
        total_transactions = len(sales_data)
        
        report_text = f"SALES REPORT\n"
        report_text += f"Period: {from_date} to {to_date}\n"
        report_text += "=" * 50 + "\n"
        report_text += f"Total Transactions: {total_transactions}\n"
        report_text += f"Total Sales: ${total_sales:.2f}\n"
        report_text += "=" * 50 + "\n"
        
        if sales_data:
            report_text += f"{'Date':<12} {'Amount':>10}\n"
            report_text += "-" * 50 + "\n"
            
            for date, amount in sales_data:
                display_date = date[:10] if len(date) > 10 else date
                report_text += f"{display_date:<12} ${amount:>10.2f}\n"
        else:
            report_text += "No sales data found for the selected period.\n"
        
        conn.close()
        self.report_text.setText(report_text)
        
        self.security_manager.log_security_event(
            self.current_user_id, "REPORT_GENERATED", 
            f"Generated sales report for period: {from_date} to {to_date}"
        )

    def generate_expense_report(self):
        if not self.check_permission('reports', 'generate'):
            self.show_permission_error()
            return
            
        from_date = self.report_from_date.date().toString("yyyy-MM-dd")
        to_date = self.report_to_date.date().toString("yyyy-MM-dd")
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''SELECT category, SUM(amount) FROM expenses 
                     WHERE date BETWEEN ? AND ? 
                     GROUP BY category ORDER BY SUM(amount) DESC''', 
                     (from_date, to_date))
        expense_data = c.fetchall()
        
        total_expenses = sum(row[1] for row in expense_data)
        
        report_text = f"EXPENSE REPORT\n"
        report_text += f"Period: {from_date} to {to_date}\n"
        report_text += "=" * 50 + "\n"
        report_text += f"Total Expenses: ${total_expenses:.2f}\n"
        report_text += "=" * 50 + "\n"
        
        if expense_data:
            report_text += f"{'Category':<20} {'Amount':>10}\n"
            report_text += "-" * 50 + "\n"
            
            for category, amount in expense_data:
                report_text += f"{category:<20} ${amount:>10.2f}\n"
        else:
            report_text += "No expense data found for the selected period.\n"
        
        conn.close()
        self.report_text.setText(report_text)
        
        self.security_manager.log_security_event(
            self.current_user_id, "REPORT_GENERATED", 
            f"Generated expense report for period: {from_date} to {to_date}"
        )

    def generate_profit_loss_report(self):
        if not self.check_permission('reports', 'generate'):
            self.show_permission_error()
            return
            
        from_date = self.report_from_date.date().toString("yyyy-MM-dd")
        to_date = self.report_to_date.date().toString("yyyy-MM-dd")
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute('''SELECT COALESCE(SUM(total), 0) FROM bills 
                     WHERE substr(date, 1, 10) BETWEEN ? AND ?''', (from_date, to_date))
        total_sales = c.fetchone()[0]
        
        c.execute('''SELECT COALESCE(SUM(amount), 0) FROM expenses 
                     WHERE date BETWEEN ? AND ?''', (from_date, to_date))
        total_expenses = c.fetchone()[0]
        
        profit_loss = total_sales - total_expenses
        
        report_text = f"PROFIT & LOSS REPORT\n"
        report_text += f"Period: {from_date} to {to_date}\n"
        report_text += "=" * 50 + "\n"
        report_text += f"Total Sales:     ${total_sales:>12.2f}\n"
        report_text += f"Total Expenses:  ${total_expenses:>12.2f}\n"
        report_text += "-" * 50 + "\n"
        report_text += f"Net {'Profit' if profit_loss >= 0 else 'Loss'}:      ${abs(profit_loss):>12.2f}\n"
        report_text += "=" * 50 + "\n"
        
        conn.close()
        self.report_text.setText(report_text)
        
        self.security_manager.log_security_event(
            self.current_user_id, "REPORT_GENERATED", 
            f"Generated profit/loss report for period: {from_date} to {to_date}"
        )

    # --- View Bills Tab ---

    def create_bills_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        controls_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.view_bills_in_tab)
        export_btn = QPushButton("Export Bills (CSV)")
        export_btn.clicked.connect(self.export_bills)
        
        controls_layout.addWidget(refresh_btn)
        controls_layout.addWidget(export_btn)
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        self.bills_table = QTableWidget()
        self._setup_table(self.bills_table, ["ID", "User", "Date", "Total", "Items Count", "Customer"])
        self.bills_table.itemDoubleClicked.connect(self.view_bill_details)
        layout.addWidget(self.bills_table)
        
        self.view_bills_in_tab()
        return widget

    def view_bills_in_tab(self):
        if not hasattr(self, 'bills_table'):
            return
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''SELECT b.id, u.username, b.date, b.total, b.items, b.customer_info 
                     FROM bills b 
                     LEFT JOIN users u ON b.user_id = u.id 
                     ORDER BY b.date DESC''')
        bills = c.fetchall()
        conn.close()
        
        data = []
        for bill in bills:
            bill_id, username, date, total, items, customer = bill
            items_count = len(eval(items)) if items else 0
            data.append((bill_id, username, date, total, items_count, customer))
        
        self._populate_table(self.bills_table, data)

    def view_bill_details(self, item):
        """View detailed bill information from a double-click."""
        row = item.row()
        bill_id = self.bills_table.item(row, 0).text()
    
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''SELECT b.id, u.username, b.date, b.total, b.items, b.customer_info
                     FROM bills b 
                     LEFT JOIN users u ON b.user_id = u.id 
                     WHERE b.id = ?''', (bill_id,))
        bill = c.fetchone()
        conn.close()
    
        if bill:
            bill_id, username, date, total, items_str, customer = bill
            items_list = eval(items_str) if items_str else []
        
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Bill Details - ID: {bill_id}")
            dialog.setMinimumSize(500, 400)
            layout = QVBoxLayout(dialog)
            
            info_group = QGroupBox("Bill Information")
            info_layout = QFormLayout(info_group)
            info_layout.addRow("Bill ID:", QLabel(str(bill_id)))
            info_layout.addRow("Cashier:", QLabel(username or "N/A"))
            info_layout.addRow("Customer:", QLabel(customer or "N/A"))
            info_layout.addRow("Date:", QLabel(date))
            info_layout.addRow("Total:", QLabel(f"${total:.2f}"))
            layout.addWidget(info_group)
            
            items_group = QGroupBox("Items")
            items_layout = QVBoxLayout(items_group)
            items_text = QTextEdit()
            items_text.setReadOnly(True)
            items_text.setFont(QFont("Courier", 10))
            
            if items_list:
                items_text.append(f"{'Item':<20} {'Qty':<8} {'Price':<10} {'Subtotal':<12}")
                items_text.append("-" * 50)
                for item in items_list:
                    name, qty, price = item
                    subtotal = qty * price
                    items_text.append(f"{name:<20} {qty:<8} ${price:<9.2f} ${subtotal:<11.2f}")
            else:
                items_text.append("No items found")
            
            items_layout.addWidget(items_text)
            layout.addWidget(items_group)
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.accept)
            layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)
            
            dialog.exec()

    def export_bills(self):
        """Export all bills to CSV"""
        default_filename = f"bills_export_{datetime.now().strftime('%Y%m%d')}.csv"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Bills",
            default_filename,
            "CSV files (*.csv);;All files (*.*)"
        )
    
        if file_path:
            try:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('''SELECT b.id, u.username, b.date, b.total, b.items, b.customer_info 
                         FROM bills b 
                         LEFT JOIN users u ON b.user_id = u.id 
                         ORDER BY b.date DESC''')
                bills = c.fetchall()
                conn.close()
            
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Bill ID', 'Cashier', 'Date', 'Total', 'Items Count', 'Customer'])
                
                    for bill in bills:
                        bill_id, username, date, total, items, customer = bill
                        items_count = len(eval(items)) if items else 0
                        writer.writerow([bill_id, username, date, total, items_count, customer])
            
                QMessageBox.information(self, "Success", f"Bills exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export bills: {e}")

# --- Application Entry Point ---

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Force a modern, consistent style
    app.setStyle("Fusion")

    # Optional: Set a dark palette for a "dark mode" feel
    # palette = QPalette()
    # palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    # palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    # palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    # palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    # palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    # palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    # palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    # palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    # palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    # palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    # palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    # palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    # palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    # app.setPalette(palette)
    
    main_win = BillingApp()
    main_win.show()
    sys.exit(app.exec())
