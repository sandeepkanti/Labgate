import os
import sys
import time
import hashlib
import sqlite3
import datetime
import threading
import json
import subprocess
import platform
from pathlib import Path
import tempfile

class OSWatchdog:
    """
    OS Corruption and Integrity Watchdog Monitor
    Tracks critical system files, registry changes, and system integrity
    """
    
    def __init__(self, usn, activity_logger):
        self.usn = usn
        self.log_activity = activity_logger
        self.monitoring = True
        self.system_baseline = {}
        self.critical_paths = self._get_critical_paths()
        self.integrity_db = "system_integrity.db"
        self.check_interval = 30  # Check every 30 seconds
        self.db_retry_count = 0
        self.max_db_retries = 3
        self.fallback_mode = False
        self.memory_cache = {}
        
        # Initialize integrity database with error handling
        self._init_integrity_db()
        
        # Create baseline on first run
        self._create_system_baseline()
    
    def _get_critical_paths(self):
        """Get list of critical system paths to monitor"""
        if platform.system() == "Windows":
            return [
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\System32\\kernel32.dll",
                "C:\\Windows\\System32\\ntdll.dll",
                "C:\\Windows\\System32\\user32.dll",
                "C:\\Windows\\System32\\advapi32.dll",
                "C:\\Windows\\System32\\shell32.dll",
                "C:\\Windows\\System32\\winlogon.exe",
                "C:\\Windows\\System32\\explorer.exe",
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\System32\\lsass.exe",
                "C:\\Windows\\System32\\csrss.exe",
                "C:\\Windows\\System32\\smss.exe",
                "C:\\Windows\\System32\\wininit.exe",
                "C:\\Windows\\System32\\services.exe"
            ]
        else:
            return [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/etc/fstab",
                "/etc/sudoers",
                "/bin/bash",
                "/bin/sh",
                "/usr/bin/sudo",
                "/usr/bin/su",
                "/sbin/init"
            ]
    
    def _get_db_connection(self, timeout=10):
        """Get database connection with timeout and retry logic"""
        for attempt in range(self.max_db_retries):
            try:
                conn = sqlite3.connect(self.integrity_db, timeout=timeout)
                conn.execute("PRAGMA journal_mode=WAL")  # Enable WAL mode for better concurrency
                conn.execute("PRAGMA busy_timeout=30000")  # 30 second busy timeout
                return conn
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower():
                    self.log_activity(self.usn, "WATCHDOG_WARNING", 
                                    f"Database locked, attempt {attempt + 1}/{self.max_db_retries}", "WARNING")
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    raise e
            except Exception as e:
                self.log_activity(self.usn, "WATCHDOG_ERROR", 
                                f"Database connection error: {str(e)}", "ERROR")
                if attempt == self.max_db_retries - 1:
                    self._enable_fallback_mode()
                    return None
                time.sleep(1)
        
        self._enable_fallback_mode()
        return None
    
    def _enable_fallback_mode(self):
        """Enable fallback mode when database is unavailable"""
        if not self.fallback_mode:
            self.fallback_mode = True
            self.log_activity(self.usn, "WATCHDOG_FALLBACK", 
                            "Enabling fallback mode - using memory cache for integrity data", "WARNING")
    
    def _init_integrity_db(self):
        """Initialize the system integrity database with error handling"""
        try:
            # Try to create database in current directory first
            conn = self._get_db_connection()
            if conn is None:
                # Try alternative location in temp directory
                temp_dir = tempfile.gettempdir()
                self.integrity_db = os.path.join(temp_dir, f"integrity_{self.usn}.db")
                self.log_activity(self.usn, "WATCHDOG_INFO", 
                                f"Using alternative database location: {self.integrity_db}", "INFO")
                conn = self._get_db_connection()
            
            if conn is None:
                self._enable_fallback_mode()
                return
            
            c = conn.cursor()
            
            # System file integrity table
            c.execute('''
                CREATE TABLE IF NOT EXISTS file_integrity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER,
                    last_modified TEXT,
                    baseline_timestamp TEXT,
                    status TEXT DEFAULT 'CLEAN'
                )
            ''')
            
            # System corruption events table
            c.execute('''
                CREATE TABLE IF NOT EXISTS corruption_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    USN TEXT,
                    event_type TEXT,
                    file_path TEXT,
                    description TEXT,
                    severity TEXT,
                    timestamp TEXT,
                    resolved BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # System health metrics table
            c.execute('''
                CREATE TABLE IF NOT EXISTS system_health (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    USN TEXT,
                    metric_name TEXT,
                    metric_value TEXT,
                    threshold_exceeded BOOLEAN,
                    timestamp TEXT
                )
            ''')
            
            # Boot integrity table
            c.execute('''
                CREATE TABLE IF NOT EXISTS boot_integrity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    USN TEXT,
                    boot_time TEXT,
                    boot_duration REAL,
                    unexpected_shutdown BOOLEAN,
                    system_errors INTEGER,
                    timestamp TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
            self.log_activity(self.usn, "WATCHDOG_INIT", 
                            "Integrity database initialized successfully", "INFO")
            
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Failed to initialize integrity database: {str(e)}", "ERROR")
            self._enable_fallback_mode()
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return None
    
    def _get_file_info(self, file_path):
        """Get file information including size and modification time"""
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'hash': self._calculate_file_hash(file_path)
            }
        except Exception:
            return None
    
    def _create_system_baseline(self):
        """Create baseline of critical system files"""
        try:
            baseline_time = datetime.datetime.now().isoformat()
            
            for file_path in self.critical_paths:
                if os.path.exists(file_path):
                    file_info = self._get_file_info(file_path)
                    if file_info:
                        self.system_baseline[file_path] = file_info
                        
                        # Try to store in database, fallback to memory if needed
                        if not self.fallback_mode:
                            conn = self._get_db_connection()
                            if conn:
                                try:
                                    c = conn.cursor()
                                    c.execute("SELECT id FROM file_integrity WHERE file_path=?", (file_path,))
                                    if not c.fetchone():
                                        c.execute('''
                                            INSERT INTO file_integrity 
                                            (file_path, file_hash, file_size, last_modified, baseline_timestamp)
                                            VALUES (?, ?, ?, ?, ?)
                                        ''', (file_path, file_info['hash'], file_info['size'], 
                                             file_info['modified'], baseline_time))
                                    conn.commit()
                                    conn.close()
                                except Exception as e:
                                    conn.close()
                                    self.log_activity(self.usn, "WATCHDOG_WARNING", 
                                                    f"Database write failed, using memory cache: {str(e)}", "WARNING")
                        
                        # Always store in memory cache as backup
                        self.memory_cache[file_path] = file_info
            
            self.log_activity(self.usn, "WATCHDOG_INIT", 
                            f"System baseline created for {len(self.system_baseline)} critical files", "INFO")
            
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Failed to create system baseline: {str(e)}", "ERROR")
    
    def _check_file_integrity(self):
        """Check integrity of critical system files"""
        corrupted_files = []
        
        try:
            for file_path in self.critical_paths:
                if os.path.exists(file_path):
                    current_info = self._get_file_info(file_path)
                    baseline_info = self.system_baseline.get(file_path) or self.memory_cache.get(file_path)
                    
                    if baseline_info and current_info:
                        # Check if file has been modified
                        if current_info['hash'] != baseline_info['hash']:
                            corrupted_files.append({
                                'path': file_path,
                                'type': 'HASH_MISMATCH',
                                'baseline_hash': baseline_info['hash'],
                                'current_hash': current_info['hash']
                            })
                        
                        # Check if file size changed significantly
                        size_diff = abs(current_info['size'] - baseline_info['size'])
                        if size_diff > 1024:  # More than 1KB difference
                            corrupted_files.append({
                                'path': file_path,
                                'type': 'SIZE_CHANGE',
                                'baseline_size': baseline_info['size'],
                                'current_size': current_info['size']
                            })
                        
                        # Update memory cache
                        self.memory_cache[file_path] = current_info
                else:
                    # Critical file is missing
                    if file_path in self.system_baseline or file_path in self.memory_cache:
                        baseline_info = self.system_baseline.get(file_path) or self.memory_cache.get(file_path)
                        corrupted_files.append({
                            'path': file_path,
                            'type': 'FILE_MISSING',
                            'baseline_hash': baseline_info['hash'] if baseline_info else 'unknown'
                        })
            
            # Log corruption events
            if corrupted_files:
                self._log_corruption_events(corrupted_files)
            
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"File integrity check failed: {str(e)}", "ERROR")
    
    def _log_corruption_events(self, corrupted_files):
        """Log corruption events to database or memory"""
        try:
            timestamp = datetime.datetime.now().isoformat()
            
            for corruption in corrupted_files:
                event_type = corruption['type']
                file_path = corruption['path']
                
                if event_type == 'HASH_MISMATCH':
                    description = f"File hash changed from {corruption['baseline_hash'][:16]}... to {corruption['current_hash'][:16]}..."
                    severity = "CRITICAL"
                elif event_type == 'SIZE_CHANGE':
                    description = f"File size changed from {corruption['baseline_size']} to {corruption['current_size']} bytes"
                    severity = "WARNING"
                elif event_type == 'FILE_MISSING':
                    description = f"Critical system file is missing (baseline hash: {corruption['baseline_hash'][:16]}...)"
                    severity = "CRITICAL"
                else:
                    description = f"Unknown corruption type: {event_type}"
                    severity = "ERROR"
                
                # Try database first, fallback to memory
                if not self.fallback_mode:
                    conn = self._get_db_connection()
                    if conn:
                        try:
                            c = conn.cursor()
                            c.execute('''
                                INSERT INTO corruption_events 
                                (USN, event_type, file_path, description, severity, timestamp)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (self.usn, event_type, file_path, description, severity, timestamp))
                            conn.commit()
                            conn.close()
                        except Exception as e:
                            conn.close()
                            self._store_event_in_memory(event_type, file_path, description, severity, timestamp)
                    else:
                        self._store_event_in_memory(event_type, file_path, description, severity, timestamp)
                else:
                    self._store_event_in_memory(event_type, file_path, description, severity, timestamp)
                
                # Log to main activity log
                self.log_activity(self.usn, "OS_CORRUPTION", description, severity)
            
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Failed to log corruption events: {str(e)}", "ERROR")
    
    def _store_event_in_memory(self, event_type, file_path, description, severity, timestamp):
        """Store corruption event in memory cache"""
        if 'corruption_events' not in self.memory_cache:
            self.memory_cache['corruption_events'] = []
        
        self.memory_cache['corruption_events'].append({
            'event_type': event_type,
            'file_path': file_path,
            'description': description,
            'severity': severity,
            'timestamp': timestamp
        })
        
        # Keep only last 100 events in memory
        if len(self.memory_cache['corruption_events']) > 100:
            self.memory_cache['corruption_events'] = self.memory_cache['corruption_events'][-100:]
    
    def _check_system_health(self):
        """Check overall system health metrics"""
        try:
            health_metrics = {}
            
            # Check disk space
            for partition in ['C:\\', '/', '/home', '/tmp']:
                try:
                    if os.path.exists(partition):
                        if hasattr(os, 'statvfs'):
                            statvfs = os.statvfs(partition)
                            free_space = statvfs.f_frsize * statvfs.f_bavail
                            total_space = statvfs.f_frsize * statvfs.f_blocks
                            usage_percent = ((total_space - free_space) / total_space) * 100
                            health_metrics[f'disk_usage_{partition.replace(":", "").replace("/", "_")}'] = usage_percent
                except:
                    pass
            
            # Check memory usage if psutil is available
            try:
                import psutil
                memory = psutil.virtual_memory()
                health_metrics['memory_usage'] = memory.percent
                health_metrics['swap_usage'] = psutil.swap_memory().percent
                health_metrics['cpu_usage'] = psutil.cpu_percent(interval=1)
                health_metrics['process_count'] = len(psutil.pids())
            except ImportError:
                pass
            
            # Log health metrics
            self._log_health_metrics(health_metrics)
            
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"System health check failed: {str(e)}", "ERROR")
    
    def _log_health_metrics(self, metrics):
        """Log system health metrics"""
        try:
            timestamp = datetime.datetime.now().isoformat()
            
            for metric_name, value in metrics.items():
                threshold_exceeded = False
                
                # Define thresholds
                if 'disk_usage' in metric_name and value > 90:
                    threshold_exceeded = True
                elif 'memory_usage' in metric_name and value > 85:
                    threshold_exceeded = True
                elif 'cpu_usage' in metric_name and value > 90:
                    threshold_exceeded = True
                elif 'process_count' in metric_name and value > 500:
                    threshold_exceeded = True
                
                # Try database first, fallback to memory
                if not self.fallback_mode:
                    conn = self._get_db_connection()
                    if conn:
                        try:
                            c = conn.cursor()
                            c.execute('''
                                INSERT INTO system_health 
                                (USN, metric_name, metric_value, threshold_exceeded, timestamp)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (self.usn, metric_name, str(value), threshold_exceeded, timestamp))
                            conn.commit()
                            conn.close()
                        except Exception:
                            conn.close()
                
                if threshold_exceeded:
                    self.log_activity(self.usn, "SYSTEM_HEALTH", 
                                    f"Threshold exceeded for {metric_name}: {value}", "WARNING")
            
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Failed to log health metrics: {str(e)}", "ERROR")
    
    def _check_boot_integrity(self):
        """Check boot integrity and system startup"""
        try:
            # Get system uptime
            if platform.system() == "Windows":
                try:
                    import psutil
                    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
                    uptime = datetime.datetime.now() - boot_time
                    
                    # Check if this is a recent boot (within last hour)
                    if uptime.total_seconds() < 3600:
                        self._log_boot_event(boot_time, uptime.total_seconds())
                except ImportError:
                    pass
            else:
                try:
                    with open('/proc/uptime', 'r') as f:
                        uptime_seconds = float(f.readline().split()[0])
                    
                    if uptime_seconds < 3600:  # Recent boot
                        boot_time = datetime.datetime.now() - datetime.timedelta(seconds=uptime_seconds)
                        self._log_boot_event(boot_time, uptime_seconds)
                except:
                    pass
                    
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Boot integrity check failed: {str(e)}", "ERROR")
    
    def _log_boot_event(self, boot_time, boot_duration):
        """Log boot event to database or memory"""
        try:
            # Check for unexpected shutdown
            unexpected_shutdown = boot_duration < 60  # Less than 1 minute uptime
            timestamp = datetime.datetime.now().isoformat()
            
            # Try database first
            if not self.fallback_mode:
                conn = self._get_db_connection()
                if conn:
                    try:
                        c = conn.cursor()
                        c.execute('''
                            INSERT INTO boot_integrity 
                            (USN, boot_time, boot_duration, unexpected_shutdown, system_errors, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (self.usn, boot_time.isoformat(), boot_duration, unexpected_shutdown, 0, timestamp))
                        conn.commit()
                        conn.close()
                    except Exception:
                        conn.close()
            
            if unexpected_shutdown:
                self.log_activity(self.usn, "BOOT_ANOMALY", 
                                f"Potential unexpected shutdown detected (uptime: {boot_duration:.1f}s)", "WARNING")
            else:
                self.log_activity(self.usn, "BOOT_NORMAL", 
                                f"Normal system boot detected at {boot_time.strftime('%H:%M:%S')}", "INFO")
                
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Failed to log boot event: {str(e)}", "ERROR")
    
    def _check_registry_integrity(self):
        """Check Windows registry integrity (Windows only)"""
        if platform.system() != "Windows":
            return
            
        try:
            import winreg
            
            # Critical registry keys to monitor
            critical_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
            ]
            
            for hkey, subkey in critical_keys:
                try:
                    reg_key = winreg.OpenKey(hkey, subkey)
                    
                    # Get number of values and subkeys
                    num_values = winreg.QueryInfoKey(reg_key)[1]
                    num_subkeys = winreg.QueryInfoKey(reg_key)[0]
                    
                    # Store baseline if not exists
                    key_id = f"{hkey}\\{subkey}"
                    if not hasattr(self, 'registry_baseline'):
                        self.registry_baseline = {}
                    
                    if key_id not in self.registry_baseline:
                        self.registry_baseline[key_id] = {'values': num_values, 'subkeys': num_subkeys}
                    else:
                        baseline = self.registry_baseline[key_id]
                        if num_values != baseline['values'] or num_subkeys != baseline['subkeys']:
                            self.log_activity(self.usn, "REGISTRY_CHANGE", 
                                            f"Registry key modified: {subkey} (values: {baseline['values']}->{num_values}, subkeys: {baseline['subkeys']}->{num_subkeys})", 
                                            "WARNING")
                            self.registry_baseline[key_id] = {'values': num_values, 'subkeys': num_subkeys}
                    
                    winreg.CloseKey(reg_key)
                    
                except OSError:
                    continue
                    
        except ImportError:
            pass
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Registry integrity check failed: {str(e)}", "ERROR")
    
    def start_monitoring(self):
        """Start the watchdog monitoring in a separate thread"""
        def monitor_loop():
            self.log_activity(self.usn, "WATCHDOG_START", 
                            f"OS Corruption Watchdog started (fallback mode: {self.fallback_mode})", "INFO")
            
            while self.monitoring:
                try:
                    # Perform all integrity checks
                    self._check_file_integrity()
                    self._check_system_health()
                    self._check_boot_integrity()
                    self._check_registry_integrity()
                    
                    # Wait for next check
                    time.sleep(self.check_interval)
                    
                except Exception as e:
                    self.log_activity(self.usn, "WATCHDOG_ERROR", 
                                    f"Watchdog monitoring error: {str(e)}", "ERROR")
                    time.sleep(self.check_interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the watchdog monitoring"""
        self.monitoring = False
        self.log_activity(self.usn, "WATCHDOG_STOP", "OS Corruption Watchdog stopped", "INFO")
    
    def get_corruption_report(self):
        """Get a summary report of detected corruptions"""
        try:
            # Try database first
            if not self.fallback_mode:
                conn = self._get_db_connection()
                if conn:
                    try:
                        c = conn.cursor()
                        c.execute('''
                            SELECT event_type, file_path, description, severity, timestamp 
                            FROM corruption_events 
                            WHERE USN=? AND timestamp > datetime('now', '-24 hours')
                            ORDER BY timestamp DESC
                        ''', (self.usn,))
                        
                        events = c.fetchall()
                        conn.close()
                        return events
                    except Exception:
                        conn.close()
            
            # Fallback to memory cache
            if 'corruption_events' in self.memory_cache:
                events = []
                cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=24)
                
                for event in self.memory_cache['corruption_events']:
                    event_time = datetime.datetime.fromisoformat(event['timestamp'])
                    if event_time > cutoff_time:
                        events.append((
                            event['event_type'],
                            event['file_path'],
                            event['description'],
                            event['severity'],
                            event['timestamp']
                        ))
                
                return sorted(events, key=lambda x: x[4], reverse=True)
            
            return []
            
        except Exception as e:
            self.log_activity(self.usn, "WATCHDOG_ERROR", 
                            f"Failed to generate corruption report: {str(e)}", "ERROR")
            return []