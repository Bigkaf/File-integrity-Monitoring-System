import tkinter as tk
from tkinter import messagebox, ttk
import hashlib
import smtplib
import logging
from email.message import EmailMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_hash(filepath):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as file:
            for chunk in iter(lambda: file.read(65536), b''):  # Read in chunks efficiently
                sha256.update(chunk)
    except (PermissionError, FileNotFoundError) as e:
        logger.error(f"Error accessing file {filepath}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")
        return None
    return sha256.hexdigest()

def send_email(sender, recipient, password, subject, body):
    """Send an email notification."""
    message = EmailMessage()
    message.set_content(body)
    message['subject'] = subject
    message['from'] = sender
    message['to'] = recipient

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender, password)
            server.send_message(message)
            logging.info("Email notification sent")
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Authentication error. Please check your email credentials.")
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as e:
        logger.error(f"SMTP Connection error: {e}")
    except Exception as e:
        logger.error(f"Error sending email: {e}")

def toggle_password_visibility():
    """Toggle visibility of the password in the password entry."""
    if show_password_var.get():
        passwd_entry.config(show="")
    else:
        passwd_entry.config(show="*")

def monitor_file(filepath, usr_email, usr_passwd):
    """Monitor file integrity and send email alerts if changes are detected."""
    baseline = get_hash(filepath)

    if baseline:
        while True:
            response = messagebox.askokcancel("File Integrity Monitor", "Press OK to check file integrity.")

            if not response:
                break  # User canceled monitoring

            check = get_hash(filepath)

            if check and check != baseline:
                send_email(usr_email, usr_email, usr_passwd, "File Integrity Alert", f"Someone edited the file: {filepath}")
                messagebox.showwarning("File Integrity Alert", "Detected file modification!")
                baseline = check
            else:
                messagebox.showinfo("File Integrity", "File integrity verified. No changes detected.")

def start_monitor():
    """Start monitoring file integrity when 'Start Monitoring' button is clicked."""
    filepath = filepath_entry.get().strip()
    usr_email = email_entry.get().strip()
    usr_passwd = passwd_entry.get().strip()

    if not (filepath and usr_email and usr_passwd):
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    try:
        monitor_file(filepath, usr_email, usr_passwd)
    except Exception as e:
        logger.error(f"Error occurred during monitoring: {e}")
        messagebox.showerror("Error", f"Error occurred during monitoring:\n{e}")

# Create GUI window
root = tk.Tk()
root.title("File Integrity Monitor")

# File Path Entry
tk.Label(root, text="File Path:").grid(row=0, column=0, padx=10, pady=5)
filepath_entry = tk.Entry(root, width=50)
filepath_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=5)

# Email Entry
tk.Label(root, text="Email Address:").grid(row=1, column=0, padx=10, pady=5)
email_entry = tk.Entry(root, width=50)
email_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

# Password Entry
tk.Label(root, text="Email Password:").grid(row=2, column=0, padx=10, pady=5)
passwd_entry = tk.Entry(root, width=50, show="*")
passwd_entry.grid(row=2, column=1, padx=10, pady=5)

# Show/Hide Password Checkbox
show_password_var = tk.BooleanVar()
show_password_var.set(False)  # Default: password hidden
show_password_checkbox = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_checkbox.grid(row=2, column=2, padx=10, pady=5, sticky="w")

# Start Monitoring Button
start_button = tk.Button(root, text="Start Monitoring", command=start_monitor)
start_button.grid(row=3, column=1, padx=10, pady=10)

# Quit Button
quit_button = tk.Button(root, text="Quit", command=root.quit)
quit_button.grid(row=3, column=2, padx=10, pady=10)

# Run the main event loop
root.mainloop()
