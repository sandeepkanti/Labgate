import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import sqlite3
import datetime
import csv
import os
import sys
import threading
import time
import subprocess
import psutil
import win32api
import win32con
import win32gui
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from PIL import Image, ImageTk, ImageEnhance
from watchdog_monitor import OSWatchdog

USER_DB = "students_demo.db"
STATUS_DB = "login_status.db"
ACTIVITY_DB = "activity_logs.db"

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def init_db():
    # Initialize user database
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute('''
        CREATE TABLE users (
            USN TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    try:
        with open(resource_path("students.csv"), newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                usn = row["USN"].strip()
                name = row["Name"].strip()
                password = row["Password"].strip()
                c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", (usn, name, password))
    except FileNotFoundError:
        print("⚠️ CSV file 'students.csv' not found.")
    except Exception as e:
        print("⚠️ Error reading CSV:", e)
    conn.commit()
    conn.close()

    # Initialize login status database
    conn2 = sqlite3.connect(STATUS_DB)
    c2 = conn2.cursor()
    c2.execute('''
        CREATE TABLE IF NOT EXISTS login_status (
            USN TEXT,
            login_time TEXT,
            logout_time TEXT
        )
    ''')
    conn2.commit()
    conn2.close()

    # Initialize activity logs database
    conn3 = sqlite3.connect(ACTIVITY_DB)
    c3 = conn3.cursor()
    c3.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            USN TEXT,
            activity_type TEXT,
            description TEXT,
            timestamp TEXT,
            severity TEXT
        )
    ''')
    c3.execute('''
        CREATE TABLE IF NOT EXISTS usb_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            USN TEXT,
            device_name TEXT,
            device_id TEXT,
            action TEXT,
            timestamp TEXT
        )
    ''')
    c3.execute('''
        CREATE TABLE IF NOT EXISTS file_transfer_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            USN TEXT,
            source_path TEXT,
            destination_path TEXT,
            file_size INTEGER,
            timestamp TEXT
        )
    ''')
    conn3.commit()
    conn3.close()

def log_activity(usn, activity_type, description, severity="INFO"):
    """Log user activities to database"""
    try:
        conn = sqlite3.connect(ACTIVITY_DB, timeout=10)
        c = conn.cursor()
        c.execute("INSERT INTO activity_logs VALUES (NULL, ?, ?, ?, ?, ?)", 
                  (usn, activity_type, description, datetime.datetime.now().isoformat(), severity))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            print(f"⚠️ Activity log database locked: {description}")
        else:
            print(f"⚠️ Activity log error: {e}")
    except Exception as e:
        print(f"⚠️ Activity log error: {e}")

def log_usb_activity(usn, device_name, device_id, action):
    """Log USB device activities"""
    try:
        conn = sqlite3.connect(ACTIVITY_DB, timeout=10)
        c = conn.cursor()
        c.execute("INSERT INTO usb_logs VALUES (NULL, ?, ?, ?, ?, ?)", 
                  (usn, device_name, device_id, action, datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ USB log error: {e}")

def log_file_transfer(usn, source, destination, file_size):
    """Log file transfer activities"""
    try:
        conn = sqlite3.connect(ACTIVITY_DB, timeout=10)
        c = conn.cursor()
        c.execute("INSERT INTO file_transfer_logs VALUES (NULL, ?, ?, ?, ?, ?)", 
                  (usn, source, destination, file_size, datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ File transfer log error: {e}")

def authenticate(usn, password):
    try:
        conn = sqlite3.connect(USER_DB, timeout=10)
        c = conn.cursor()
        c.execute("SELECT name FROM users WHERE usn=? AND password=?", (usn, password))
        user = c.fetchone()
        conn.close()

        if user:
            try:
                conn2 = sqlite3.connect(STATUS_DB, timeout=10)
                c2 = conn2.cursor()
                c2.execute("INSERT INTO login_status (usn, login_time) VALUES (?, ?)", (usn, datetime.datetime.now().isoformat()))
                conn2.commit()
                conn2.close()
            except Exception as e:
                print(f"⚠️ Login status error: {e}")
            
            # Log successful login
            log_activity(usn, "LOGIN", f"User {user[0]} logged in successfully", "INFO")
            return user[0]
        else:
            # Log failed login attempt
            log_activity(usn, "LOGIN_FAILED", f"Failed login attempt for USN: {usn}", "WARNING")
        return None
    except Exception as e:
        print(f"⚠️ Authentication error: {e}")
        return None

def logout_user(usn):
    """Update logout time in database"""
    try:
        conn = sqlite3.connect(STATUS_DB, timeout=10)
        c = conn.cursor()
        c.execute("UPDATE login_status SET logout_time=? WHERE USN=? AND logout_time IS NULL", 
                  (datetime.datetime.now().isoformat(), usn))
        conn.commit()
        conn.close()
        
        # Log logout activity
        log_activity(usn, "LOGOUT", f"User logged out", "INFO")
    except Exception as e:
        print(f"⚠️ Logout error: {e}")

class SystemMonitor:
    def __init__(self, usn):
        self.usn = usn
        self.monitoring = True
        self.installed_programs = self.get_installed_programs()
        self.usb_devices = self.get_usb_devices()
        
    def get_installed_programs(self):
        """Get list of currently installed programs"""
        programs = set()
        try:
            # Check Windows registry for installed programs
            import winreg
            reg_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for reg_path in reg_paths:
                try:
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    for i in range(winreg.QueryInfoKey(reg_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(reg_key, i)
                            subkey = winreg.OpenKey(reg_key, subkey_name)
                            try:
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                programs.add(display_name)
                            except FileNotFoundError:
                                pass
                            winreg.CloseKey(subkey)
                        except OSError:
                            continue
                    winreg.CloseKey(reg_key)
                except OSError:
                    continue
        except ImportError:
            pass
        return programs
    
    def get_usb_devices(self):
        """Get list of currently connected USB devices"""
        devices = set()
        try:
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts:
                    devices.add(partition.device)
        except:
            pass
        return devices
    
    def monitor_system_changes(self):
        """Monitor for system changes in a separate thread"""
        while self.monitoring:
            try:
                # Check for software changes
                current_programs = self.get_installed_programs()
                
                # Check for newly installed programs
                new_programs = current_programs - self.installed_programs
                for program in new_programs:
                    log_activity(self.usn, "SOFTWARE_INSTALL", f"New software installed: {program}", "WARNING")
                
                # Check for uninstalled programs
                removed_programs = self.installed_programs - current_programs
                for program in removed_programs:
                    log_activity(self.usn, "SOFTWARE_UNINSTALL", f"Software removed: {program}", "CRITICAL")
                
                self.installed_programs = current_programs
                
                # Check for USB device changes
                current_usb = self.get_usb_devices()
                
                # Check for new USB devices
                new_usb = current_usb - self.usb_devices
                for device in new_usb:
                    log_usb_activity(self.usn, device, device, "CONNECTED")
                    log_activity(self.usn, "USB_CONNECT", f"USB device connected: {device}", "WARNING")
                
                # Check for removed USB devices
                removed_usb = self.usb_devices - current_usb
                for device in removed_usb:
                    log_usb_activity(self.usn, device, device, "DISCONNECTED")
                    log_activity(self.usn, "USB_DISCONNECT", f"USB device disconnected: {device}", "INFO")
                
                self.usb_devices = current_usb
                
                # Monitor file transfers to USB devices
                self.monitor_file_transfers()
                
            except Exception as e:
                log_activity(self.usn, "MONITOR_ERROR", f"System monitoring error: {str(e)}", "ERROR")
            
            time.sleep(5)  # Check every 5 seconds
    
    def monitor_file_transfers(self):
        """Monitor file transfers to removable devices"""
        try:
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts:
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        # This is a simplified check - in a real implementation,
                        # you'd want to monitor actual file operations
                        if hasattr(self, f'last_usage_{partition.device}'):
                            last_usage = getattr(self, f'last_usage_{partition.device}')
                            if usage.used > last_usage:
                                size_diff = usage.used - last_usage
                                log_file_transfer(self.usn, "SYSTEM", partition.mountpoint, size_diff)
                                log_activity(self.usn, "FILE_TRANSFER", 
                                            f"File transfer to {partition.mountpoint}: {size_diff} bytes", "WARNING")
                        setattr(self, f'last_usage_{partition.device}', usage.used)
                    except:
                        pass
        except Exception as e:
            log_activity(self.usn, "FILE_MONITOR_ERROR", f"File monitoring error: {str(e)}", "ERROR")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SUK LAB GATE - Enhanced Security System with OS Watchdog")
        self.root.attributes('-fullscreen', True)
        self.root.bind("<Escape>", lambda e: self.root.attributes('-fullscreen', False))
        
        self.current_user = None
        self.current_usn = None
        self.system_monitor = None
        self.os_watchdog = None
        self.password_visible = False

        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        
        # Background
        try:
            bg_img = Image.open(resource_path("W10.jpg")).resize((sw, sh))
            self.bg = ImageTk.PhotoImage(bg_img)
            bg_label = tk.Label(root, image=self.bg)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except:
            self.root.configure(bg="#0a183d")
        
        # Header Image - Full width at top
        try:
            header_img = Image.open(resource_path("logo.png")).resize((sw, 120))
            self.header_photo = ImageTk.PhotoImage(header_img)
            header_label = tk.Label(root, image=self.header_photo, bg="#000000", bd=0)
            header_label.place(x=0, y=0, width=sw, height=120)
        except:
            # Fallback header with full width
            header_label = tk.Label(root, text="SUK LAB SECURITY SYSTEM", 
                                  font=("Segoe UI", 20, "bold"), 
                                  fg="white", bg="#000000", bd=0)
            header_label.place(x=0, y=0, width=sw, height=120)

        # Create login interface
        self.create_login_interface()
        
        # Create logout interface (initially hidden)
        self.create_logout_interface()

    def create_login_interface(self):
        """Create the login interface"""
        # User Avatar - positioned lower to accommodate header
        try:
            avatar = Image.open(resource_path("user_icon.png")).resize((100, 100))
            self.avatar_photo = ImageTk.PhotoImage(avatar)
            self.avatar_label = tk.Label(self.root, image=self.avatar_photo, bg="#000000", bd=0)
            self.avatar_label.place(relx=0.5, rely=0.4, anchor='center')
        except:
            self.avatar_label = tk.Label(self.root, text="👤", font=("Segoe UI", 48), 
                                       bg="#000", fg="white")
            self.avatar_label.place(relx=0.5, rely=0.4, anchor='center')

        label_font = ("Segoe UI", 12)
        entry_width = 25
        entry_ipady = 3
        bg_color = "#000000"
        label_fg = "white"
        
        # USN Frame - positioned lower
        self.usn_frame = tk.Frame(self.root, bg=bg_color, bd=0)
        self.usn_frame.place(relx=0.49, rely=0.5, anchor='center')
        tk.Label(self.usn_frame, text="USN:", font=label_font, fg=label_fg, bg=bg_color).pack(side="left", padx=(0, 5))
        self.usn_var = tk.StringVar()
        self.usn_entry = ttk.Entry(self.usn_frame, textvariable=self.usn_var, font=label_font, width=entry_width)
        self.usn_entry.pack(side="left", ipady=entry_ipady)
        
        # Password Frame - positioned lower
        self.pass_frame = tk.Frame(self.root, bg=bg_color, bd=0)
        self.pass_frame.place(relx=0.5, rely=0.58, anchor='center')
        tk.Label(self.pass_frame, text="PASS:", font=label_font, fg=label_fg, bg=bg_color).pack(side="left", padx=(0, 5))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(self.pass_frame, textvariable=self.pass_var, font=label_font, show="*", width=entry_width-3)
        self.pass_entry.pack(side="left", ipady=entry_ipady)
        
        # Show/Hide Password Button
        self.show_pass_btn = ttk.Button(self.pass_frame, text="👁", width=3, command=self.toggle_password_visibility)
        self.show_pass_btn.pack(side="left", padx=(2, 2), ipady=4)
        
        # Login Button
        self.login_button = ttk.Button(self.pass_frame, text="→", width=2, command=self.login)
        self.login_button.pack(side="left", padx=(2, 0), ipady=4)
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.login())

    def create_logout_interface(self):
        """Create the logout interface (hidden initially)"""
        # Welcome message and logout button
        self.welcome_frame = tk.Frame(self.root, bg="#000000", bd=0)
        
        self.welcome_label = tk.Label(self.welcome_frame, text="", 
                                    font=("Segoe UI", 16, "bold"), 
                                    fg="white", bg="#000000")
        self.welcome_label.pack(pady=10)
        
        self.status_label = tk.Label(self.welcome_frame, text="System monitoring & OS watchdog active...", 
                                   font=("Segoe UI", 12), 
                                   fg="lime", bg="#000000")
        self.status_label.pack(pady=5)
        
        # Security status indicators
        self.security_frame = tk.Frame(self.welcome_frame, bg="#000000")
        self.security_frame.pack(pady=10)
        
        self.integrity_status = tk.Label(self.security_frame, text="🛡️ File Integrity: OK", 
                                       font=("Segoe UI", 10), fg="lime", bg="#000000")
        self.integrity_status.pack(side="left", padx=10)
        
        self.health_status = tk.Label(self.security_frame, text="💚 System Health: OK", 
                                    font=("Segoe UI", 10), fg="lime", bg="#000000")
        self.health_status.pack(side="left", padx=10)
        
        self.watchdog_status = tk.Label(self.security_frame, text="👁️ Watchdog: Active", 
                                      font=("Segoe UI", 10), fg="lime", bg="#000000")
        self.watchdog_status.pack(side="left", padx=10)
        
        # Control buttons
        self.control_frame = tk.Frame(self.welcome_frame, bg="#000000")
        self.control_frame.pack(pady=10)
        
        self.corruption_report_btn = ttk.Button(self.control_frame, text="Corruption Report", 
                                              command=self.show_corruption_report)
        self.corruption_report_btn.pack(side="left", padx=5)
        
        self.logout_button = ttk.Button(self.control_frame, text="Logout", 
                                      command=self.logout, style="danger.TButton")
        self.logout_button.pack(side="left", padx=5)
        
        # Activity log display
        self.activity_frame = tk.Frame(self.welcome_frame, bg="#000000")
        self.activity_frame.pack(pady=10, fill="both", expand=True)
        
        tk.Label(self.activity_frame, text="Recent Activity & Security Events:", 
               font=("Segoe UI", 12, "bold"), fg="white", bg="#000000").pack()
        
        self.activity_text = tk.Text(self.activity_frame, height=12, width=100, 
                                   bg="#1a1a1a", fg="white", font=("Consolas", 9))
        self.activity_text.pack(pady=5)
        
        # Initially hide the logout interface
        self.welcome_frame.place_forget()

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.password_visible:
            self.pass_entry.configure(show="*")
            self.show_pass_btn.configure(text="👁")
            self.password_visible = False
        else:
            self.pass_entry.configure(show="")
            self.show_pass_btn.configure(text="🙈")
            self.password_visible = True

    def login(self):
        """Handle user login"""
        usn = self.usn_var.get().strip()
        pwd = self.pass_entry.get().strip()
        
        if not usn or not pwd:
            messagebox.showwarning("Missing Info", "Please enter both USN and Password.")
            return
        
        name = authenticate(usn, pwd)
        if name:
            self.current_user = name
            self.current_usn = usn
            
            # Hide login interface
            self.avatar_label.place_forget()
            self.usn_frame.place_forget()
            self.pass_frame.place_forget()
            
            # Show logout interface - positioned lower to accommodate header
            self.welcome_label.configure(text=f"Welcome, {name}!")
            self.welcome_frame.place(relx=0.5, rely=0.6, anchor='center')
            
            # Start system monitoring
            self.system_monitor = SystemMonitor(usn)
            monitor_thread = threading.Thread(target=self.system_monitor.monitor_system_changes, daemon=True)
            monitor_thread.start()
            
            # Start OS Watchdog with error handling
            try:
                self.os_watchdog = OSWatchdog(usn, log_activity)
                self.os_watchdog.start_monitoring()
                watchdog_status = "enabled"
            except Exception as e:
                log_activity(usn, "WATCHDOG_ERROR", f"Failed to start OS Watchdog: {str(e)}", "ERROR")
                watchdog_status = "failed to start"
                self.watchdog_status.configure(text="⚠️ Watchdog: Error", fg="orange")
            
            # Start activity log updates
            self.update_activity_log()
            
            # Start security status updates
            self.update_security_status()
            
            messagebox.showinfo("Success", f"Welcome, {name}!\nSystem monitoring and OS watchdog are now active.")
        else:
            messagebox.showerror("Login Failed", "Incorrect USN or Password.")
            # Clear password field
            self.pass_var.set("")

    def logout(self):
        """Handle user logout"""
        if self.current_usn:
            logout_user(self.current_usn)
            
            if self.system_monitor:
                self.system_monitor.stop_monitoring()
            
            if self.os_watchdog:
                try:
                    self.os_watchdog.stop_monitoring()
                except Exception as e:
                    print(f"⚠️ Error stopping watchdog: {e}")
            
            messagebox.showinfo("Logout", f"Goodbye, {self.current_user}!")
            
            # Reset interface
            self.welcome_frame.place_forget()
            self.create_login_interface()
            
            # Clear variables
            self.current_user = None
            self.current_usn = None
            self.system_monitor = None
            self.os_watchdog = None
            self.usn_var.set("")
            self.pass_var.set("")

    def update_activity_log(self):
        """Update the activity log display"""
        if self.current_usn:
            try:
                conn = sqlite3.connect(ACTIVITY_DB, timeout=5)
                c = conn.cursor()
                c.execute("""
                    SELECT activity_type, description, timestamp, severity 
                    FROM activity_logs 
                    WHERE USN=? 
                    ORDER BY timestamp DESC 
                    LIMIT 25
                """, (self.current_usn,))
                
                activities = c.fetchall()
                conn.close()
                
                # Clear and update activity text
                self.activity_text.delete(1.0, tk.END)
                for activity in activities:
                    activity_type, description, timestamp, severity = activity
                    time_str = datetime.datetime.fromisoformat(timestamp).strftime("%H:%M:%S")
                    
                    # Color code by severity
                    if severity == "CRITICAL":
                        color_prefix = "🔴"
                    elif severity == "WARNING":
                        color_prefix = "🟡"
                    elif severity == "ERROR":
                        color_prefix = "🟠"
                    else:
                        color_prefix = "🟢"
                    
                    log_line = f"[{time_str}] {color_prefix} {severity}: {description}\n"
                    self.activity_text.insert(tk.END, log_line)
                
                # Auto-scroll to bottom
                self.activity_text.see(tk.END)
                
            except Exception as e:
                print(f"Error updating activity log: {e}")
            
            # Schedule next update
            self.root.after(3000, self.update_activity_log)  # Update every 3 seconds

    def update_security_status(self):
        """Update security status indicators"""
        if self.current_usn and self.os_watchdog:
            try:
                # Get corruption events from last hour
                corruption_events = self.os_watchdog.get_corruption_report()
                
                # Update integrity status
                critical_events = [e for e in corruption_events if e[3] == "CRITICAL"]
                if critical_events:
                    self.integrity_status.configure(text="🔴 File Integrity: COMPROMISED", fg="red")
                else:
                    self.integrity_status.configure(text="🛡️ File Integrity: OK", fg="lime")
                
                # Update health status (simplified)
                warning_events = [e for e in corruption_events if e[3] == "WARNING"]
                if len(warning_events) > 5:
                    self.health_status.configure(text="🟡 System Health: DEGRADED", fg="yellow")
                else:
                    self.health_status.configure(text="💚 System Health: OK", fg="lime")
                
                # Update watchdog status
                if self.os_watchdog.fallback_mode:
                    self.watchdog_status.configure(text="⚠️ Watchdog: Fallback Mode", fg="orange")
                else:
                    self.watchdog_status.configure(text="👁️ Watchdog: Active", fg="lime")
                
            except Exception as e:
                print(f"Error updating security status: {e}")
                self.watchdog_status.configure(text="❌ Watchdog: Error", fg="red")
            
            # Schedule next update
            self.root.after(10000, self.update_security_status)  # Update every 10 seconds

    def show_corruption_report(self):
        """Show detailed corruption report in a new window"""
        if not self.os_watchdog:
            messagebox.showwarning("Watchdog Inactive", "OS Watchdog is not currently active.")
            return
        
        try:
            corruption_events = self.os_watchdog.get_corruption_report()
            
            # Create report window
            report_window = tk.Toplevel(self.root)
            report_window.title("OS Corruption Report - Last 24 Hours")
            report_window.geometry("800x600")
            report_window.configure(bg="#1a1a1a")
            
            # Report header
            header_text = "OS Corruption & Integrity Report"
            if self.os_watchdog.fallback_mode:
                header_text += " (Fallback Mode)"
            
            header_label = tk.Label(report_window, text=header_text, 
                                  font=("Segoe UI", 16, "bold"), fg="white", bg="#1a1a1a")
            header_label.pack(pady=10)
            
            # Report text area
            report_text = tk.Text(report_window, bg="#2a2a2a", fg="white", 
                                font=("Consolas", 10), wrap=tk.WORD)
            report_text.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Populate report
            if corruption_events:
                report_text.insert(tk.END, f"Found {len(corruption_events)} security events in the last 24 hours:\n\n")
                
                for i, event in enumerate(corruption_events, 1):
                    event_type, file_path, description, severity, timestamp = event
                    time_str = datetime.datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                    
                    report_text.insert(tk.END, f"{i}. [{time_str}] {severity}\n")
                    report_text.insert(tk.END, f"   Type: {event_type}\n")
                    report_text.insert(tk.END, f"   File: {file_path}\n")
                    report_text.insert(tk.END, f"   Description: {description}\n\n")
            else:
                report_text.insert(tk.END, "No corruption events detected in the last 24 hours.\n")
                report_text.insert(tk.END, "System integrity appears to be intact.\n\n")
                report_text.insert(tk.END, "Watchdog is actively monitoring:\n")
                report_text.insert(tk.END, "• Critical system files\n")
                report_text.insert(tk.END, "• Registry integrity\n")
                report_text.insert(tk.END, "• System health metrics\n")
                report_text.insert(tk.END, "• Boot integrity\n")
            
            if self.os_watchdog.fallback_mode:
                report_text.insert(tk.END, "\n⚠️ Note: Watchdog is running in fallback mode due to database issues.\n")
                report_text.insert(tk.END, "Some historical data may be limited to current session.\n")
            
            report_text.configure(state="disabled")
            
            # Close button
            close_btn = ttk.Button(report_window, text="Close", 
                                 command=report_window.destroy)
            close_btn.pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate corruption report: {str(e)}")

if __name__ == "__main__":
    init_db()
    root = ttk.Window(themename="darkly")
    app = LoginApp(root)
    root.mainloop()