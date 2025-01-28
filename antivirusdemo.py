
# Example virus signatures - in a real system this should be loaded from a database or current API
VIRUS_SIGNATURES = {
    "malware1": "e4968ef99266df7c9a1f0637d2389dab",  # Example malware hash
    "malware2": "a2b824bf51e1d7d281da3fe940147224",
    "ransomware1": "f8e966d1137c4c7c6331ff4c5b4f4398",
    "trojan1": "c2b45ab412d0781a1d8d87829e3d0848"
}

# Global variables for real-time protection
realtime_protection = True
observer = None


def scan_new_file(file_path):
    try:
        is_safe = scan_file(file_path)
        if not is_safe:
            messagebox.showwarning("Threat Detected!",
                                   f"Threat detected in newly created file:\n{file_path}")
    except:
        pass


class FileEventHandler(watchdog.events.FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and realtime_protection:
            file_path = event.src_path
            threading.Thread(target=scan_new_file, args=(file_path,)).start()


def start_realtime_protection():
    global observer
    if observer is None:
        event_handler = FileEventHandler()
        observer = watchdog.observers.Observer()

        # Watch important system folders
        paths_to_watch = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop")
        ]

        for path in paths_to_watch:
            if os.path.exists(path):
                observer.schedule(event_handler, path, recursive=False)

        observer.start()


def stop_realtime_protection():
    global observer
    if observer:
        observer.stop()
        observer.join()
        observer = None


def calculate_file_hash(file_path):
    """Calculates MD5 hash of the file"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return None


def scan_file(file_path):
    """Checks file against virus signatures"""
    time.sleep(0.1)  # Scan simulation
    try:
        file_hash = calculate_file_hash(file_path)
        if file_hash:
            # Signature check
            for virus_name, virus_hash in VIRUS_SIGNATURES.items():
                if file_hash == virus_hash:
                    return False  # Malware detected
        return True  # Safe
    except:
        return False


def show_scan_results(suspicious_files, quarantined_files):
    results_window = Toplevel()
    results_window.title("Scan Results")
    results_window.geometry("800x600")
    results_window.configure(bg="#f0f0f0")
    center_window(results_window)

    # Title
    title_label = ttk.Label(results_window, text="Scan Results", font=("Arial", 16, "bold"))
    title_label.pack(pady=20)

    # Create notebook
    notebook = ttk.Notebook(results_window)
    notebook.pack(fill=BOTH, expand=True, padx=20, pady=20)

    # Suspicious files tab
    suspicious_frame = ttk.Frame(notebook)
    notebook.add(suspicious_frame, text="Suspicious Files")

    suspicious_tree = ttk.Treeview(suspicious_frame, columns=("File Path", "Threat Type"), show="headings")
    suspicious_tree.heading("File Path", text="File Path")
    suspicious_tree.heading("Threat Type", text="Threat Type")
    suspicious_tree.column("File Path", width=400)
    suspicious_tree.column("Threat Type", width=200)

    for file_path in suspicious_files:
        suspicious_tree.insert("", END, values=(file_path, "Suspicious File"))

    suspicious_scroll = ttk.Scrollbar(suspicious_frame, orient=VERTICAL, command=suspicious_tree.yview)
    suspicious_tree.configure(yscrollcommand=suspicious_scroll.set)

    suspicious_tree.pack(side=LEFT, fill=BOTH, expand=True)
    suspicious_scroll.pack(side=RIGHT, fill=Y)

    # Quarantine tab
    quarantine_frame = ttk.Frame(notebook)
    notebook.add(quarantine_frame, text="Quarantine")

    quarantine_tree = ttk.Treeview(quarantine_frame, columns=("File Path", "Threat Type"), show="headings")
    quarantine_tree.heading("File Path", text="File Path")
    quarantine_tree.heading("Threat Type", text="Threat Type")
    quarantine_tree.column("File Path", width=400)
    quarantine_tree.column("Threat Type", width=200)

    for file_path in quarantined_files:
        quarantine_tree.insert("", END, values=(file_path, "In Quarantine"))

    quarantine_scroll = ttk.Scrollbar(quarantine_frame, orient=VERTICAL, command=quarantine_tree.yview)
    quarantine_tree.configure(yscrollcommand=quarantine_scroll.set)

    quarantine_tree.pack(side=LEFT, fill=BOTH, expand=True)
    quarantine_scroll.pack(side=RIGHT, fill=Y)

    # Buttons
    button_frame = ttk.Frame(results_window)
    button_frame.pack(pady=20)

    ttk.Button(button_frame, text="Clean",
               command=lambda: messagebox.showinfo("Info", "Cleaning process started")).pack(side=LEFT, padx=5)
    ttk.Button(button_frame, text="Move to Quarantine",
               command=lambda: messagebox.showinfo("Info", "Selected files moved to quarantine")).pack(side=LEFT,
                                                                                                        padx=5)
    ttk.Button(button_frame, text="Close", command=results_window.destroy).pack(side=LEFT, padx=5)


def quick_scan():
    scan_window = Toplevel()
    scan_window.title("Quick Scan")
    scan_window.geometry("600x400")
    scan_window.configure(bg="#f0f0f0")
    center_window(scan_window)

    progress = ttk.Progressbar(scan_window, mode='determinate')
    progress.pack(pady=20, padx=20, fill=X)

    status_label = ttk.Label(scan_window, text="Starting scan...")
    status_label.pack(pady=10)

    results_text = Text(scan_window, height=15, width=60)
    results_text.pack(pady=10, padx=20)

    def run_scan():
        suspicious_files = []
        quarantined_files = []
        common_paths = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")]
        total_files = 0
        scanned_files = 0

        for path in common_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    total_files += len(files)

        for path in common_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        status_label.config(text=f"Scanning: {file}")
                        is_safe = scan_file(file_path)
                        scanned_files += 1
                        progress['value'] = (scanned_files / total_files) * 100

                        if not is_safe:
                            if "virus" in file.lower() or "malware" in file.lower():
                                quarantined_files.append(file_path)
                            else:
                                suspicious_files.append(file_path)

                        results_text.insert(END, f"{file_path}: {'Safe' if is_safe else 'Threat!'}\n")
                        results_text.see(END)
                        scan_window.update()

        status_label.config(text="Scan completed!")
        show_scan_results(suspicious_files, quarantined_files)

    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()


def full_scan():
    scan_window = Toplevel()
    scan_window.title("Full Scan")
    scan_window.geometry("600x400")
    scan_window.configure(bg="#f0f0f0")
    center_window(scan_window)

    progress = ttk.Progressbar(scan_window, mode='determinate')
    progress.pack(pady=20, padx=20, fill=X)

    status_label = ttk.Label(scan_window, text="Starting full scan...")
    status_label.pack(pady=10)

    time_label = ttk.Label(scan_window, text="Estimated time: Calculating...")
    time_label.pack(pady=5).

    results_text = Text(scan_window, height=15, width=60)
    results_text.pack(pady=10, padx=20)

    # Flag to control scanning
    scanning = True
    start_time = time.time()
    processed_files = []
    suspicious_files = []
    quarantined_files = []

    def stop_scan():
        nonlocal scanning
        scanning = False
        scan_window.destroy()

    scan_window.protocol("WM_DELETE_WINDOW", stop_scan)

    def run_scan():
        # Get all drives
        import string
        from ctypes import windll

        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:")
            bitmask >>= 1

        total_files = 0
        scanned_files = 0

        # First count total files
        for drive in drives:
            if not scanning:
                return
            if os.path.exists(drive):
                try:
                    for root, dirs, files in os.walk(drive):
                        total_files += len(files)
                        status_label.config(text=f"Counting files: {total_files}")
                        scan_window.update()
                except (PermissionError, Exception):
                    continue

        # Scan all drives
        for drive in drives:
            if not scanning:
                return
            if os.path.exists(drive):
                try:
                    for root, dirs, files in os.walk(drive):
                        for file in files:
                            if not scanning:
                                return
                            try:
                                file_path = os.path.join(root, file)
                                if file_path not in processed_files:
                                    processed_files.append(file_path)
                                    status_label.config(text=f"Scanning: {file}")
                                    is_safe = scan_file(file_path)
                                    scanned_files += 1

                                    if not is_safe:
                                        if "virus" in file.lower() or "malware" in file.lower():
                                            quarantined_files.append(file_path)
                                        else:
                                            suspicious_files.append(file_path)

                                    # Calculate progress and remaining time
                                    current_progress = (scanned_files / total_files) * 100
                                    progress['value'] = current_progress

                                    elapsed_time = time.time() - start_time
                                    if elapsed_time > 0 and scanned_files > 0:
                                        files_per_second = scanned_files / elapsed_time
                                        remaining_files = total_files - scanned_files
                                        if files_per_second > 0:
                                            remaining_seconds = remaining_files / files_per_second
                                            hours = int(remaining_seconds // 3600)
                                            minutes = int((remaining_seconds % 3600) // 60)
                                            seconds = int(remaining_seconds % 60)

                                            time_str = ""
                                            if hours > 0:
                                                time_str += f"{hours} hours "
                                            if minutes > 0 or hours > 0:
                                                time_str += f"{minutes} minutes "
                                            time_str += f"{seconds} seconds"

                                            time_label.config(text=f"Estimated time remaining: {time_str}")

                                    results_text.insert(END, f"{file_path}: {'Safe' if is_safe else 'Threat!'}\n")
                                    results_text.see(END)
                                    scan_window.update()
                            except (PermissionError, OSError, Exception):
                                continue
                except (PermissionError, Exception):
                    continue

        if scanning:
            status_label.config(text="Scan completed!")
            time_label.config(text="Scan completed!")
            show_scan_results(suspicious_files, quarantined_files)

    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()


def custom_scan():
    from tkinter import filedialog
    folder = filedialog.askdirectory()
    if folder:
        scan_window = Toplevel()
        scan_window.title("Custom Scan")
        scan_window.geometry("600x400")
        scan_window.configure(bg="#f0f0f0")
        center_window(scan_window)

        progress = ttk.Progressbar(scan_window, mode='determinate')
        progress.pack(pady=20, padx=20, fill=X)

        status_label = ttk.Label(scan_window, text="Starting custom scan...")
        status_label.pack(pady=10)

        time_label = ttk.Label(scan_window, text="")
        time_label.pack(pady=5)

        results_text = Text(scan_window, height=15, width=60)
        results_text.pack(pady=10, padx=20)

        def run_scan():
            scanning = True
            total_files = 0
            scanned_files = 0
            processed_files = []
            suspicious_files = []
            quarantined_files = []
            start_time = time.time()

            # First count total files
            for root, dirs, files in os.walk(folder):
                total_files += len(files)

            if total_files == 0:
                status_label.config(text="No files found to scan!")
                return

            for root, dirs, files in os.walk(folder):
                for file in files:
                    if not scanning:
                        return
                    try:
                        file_path = os.path.join(root, file)
                        if file_path not in processed_files:
                            processed_files.append(file_path)
                            status_label.config(text=f"Scanning: {file}")
                            is_safe = scan_file(file_path)
                            scanned_files += 1

                            if not is_safe:
                                if "virus" in file.lower() or "malware" in file.lower():
                                    quarantined_files.append(file_path)
                                else:
                                    suspicious_files.append(file_path)

                            current_progress = (scanned_files / total_files) * 100
                            progress['value'] = current_progress

                            # Calculate remaining time
                            elapsed_time = time.time() - start_time
                            if elapsed_time > 0:
                                avg_time_per_file = elapsed_time / scanned_files
                                remaining_files = total_files - scanned_files
                                estimated_time = avg_time_per_file * remaining_files

                                hours = int(estimated_time // 3600)
                                minutes = int((estimated_time % 3600) // 60)
                                seconds = int(estimated_time % 60)

                                time_str = ""
                                if hours > 0:
                                    time_str += f"{hours} hours "
                                if minutes > 0 or hours > 0:
                                    time_str += f"{minutes} minutes "
                                time_str += f"{seconds} seconds"

                                time_label.config(text=f"Estimated time remaining: {time_str}")

                            results_text.insert(END, f"{file_path}: {'Safe' if is_safe else 'Threat!'}\n")
                            results_text.see(END)
                            scan_window.update()
                    except (PermissionError, OSError, Exception):
                        continue

            if scanning:
                status_label.config(text="Scan completed!")
                time_label.config(text="Scan completed!")
                show_scan_results(suspicious_files, quarantined_files)

        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()


def center_window(window):
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry('{}x{}+{}+{}'.format(width, height, x, y))


def open_settings():
    settings_window = Toplevel()
    settings_window.title("Settings")
    settings_window.geometry("600x400")
    settings_window.configure(bg="#f0f0f0")
    center_window(settings_window)

    # Create frame for settings
    settings_frame = ttk.Frame(settings_window, padding="20")
    settings_frame.pack(fill=BOTH, expand=True)

    # Title
    title_label = ttk.Label(settings_frame, text="Settings", font=("Arial", 16, "bold"))
    title_label.pack(pady=(0, 20))

    # Real-time protection setting
    realtime_var = BooleanVar(value=globals().get('realtime_protection', False))

    def toggle_realtime():
        global realtime_protection
        realtime_protection = realtime_var.get()
        if realtime_protection:
            start_realtime_protection()
            messagebox.showinfo("Info", "Real-time protection enabled!")
        else:
            stop_realtime_protection()
            messagebox.showinfo("Info", "Real-time protection disabled!")

    realtime_frame = ttk.LabelFrame(settings_frame, text="Real-time Protection", padding="10")
    realtime_frame.pack(fill=X, pady=10)

    ttk.Checkbutton(realtime_frame, text="Enable real-time protection",
                    variable=realtime_var, command=toggle_realtime).pack(anchor=W)

    ttk.Label(realtime_frame,
              text="Note: Real-time protection automatically scans\nnewly created files and blocks threats.",
              wraplength=500).pack(anchor=W, pady=(5, 0))

    # Other settings
    other_frame = ttk.LabelFrame(settings_frame, text="Other Settings", padding="10")
    other_frame.pack(fill=X, pady=10)

    ttk.Checkbutton(other_frame, text="Automatic scan").pack(anchor=W, pady=2)
    ttk.Checkbutton(other_frame, text="Run at startup").pack(anchor=W, pady=2)

    # Scan settings
    scan_frame = ttk.LabelFrame(settings_frame, text="Scan Settings", padding="10")
    scan_frame.pack(fill=X, pady=10)

    ttk.Label(scan_frame, text="Scan Frequency:").pack(anchor=W)
    ttk.Combobox(scan_frame, values=["Daily", "Weekly", "Monthly"]).pack(anchor=W, pady=(5, 10))

    # Language settings
    lang_frame = ttk.LabelFrame(settings_frame, text="Language Settings", padding="10")
    lang_frame.pack(fill=X, pady=10)

    ttk.Label(lang_frame, text="Select Language:").pack(anchor=W)
    language_combo = ttk.Combobox(lang_frame, values=["English", "Turkish", "German", "French", "Spanish"])
    language_combo.pack(anchor=W, pady=(5, 0))
    language_combo.set("English")  # Default language

    # Save button
    ttk.Button(settings_frame, text="Save", command=settings_window.destroy).pack(pady=20)


def create_database():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT NOT NULL,
                  password TEXT NOT NULL)''')
    conn.commit()
    conn.close()


def open_main_window(username):
    main_window = Toplevel()
    main_window.title("Antivirus Control Panel")
    main_window.geometry("1000x700")
    main_window.configure(bg="#f0f0f0")
    center_window(main_window)

    style = ttk.Style()
    style.configure("Main.TLabel", font=("Arial", 14, "bold"))
    style.configure("Menu.TButton", font=("Arial", 12), padding=10)

    welcome_frame = ttk.Frame(main_window)
    welcome_frame.pack(fill=X, padx=20, pady=20)
    welcome_label = ttk.Label(welcome_frame, text=f"Welcome, {username}!", style="Main.TLabel")
    welcome_label.pack(side=LEFT)

    status_label = ttk.Label(welcome_frame, text="System Status: Secure",
                             foreground="green", style="Main.TLabel")
    status_label.pack(side=RIGHT)

    menu_frame = ttk.Frame(main_window, padding="20")
    menu_frame.pack(fill=BOTH, expand=True)

    left_menu = ttk.Frame(menu_frame)
    left_menu.pack(side=LEFT, fill=Y, padx=(0, 20))

    buttons = [
        ("Quick Scan", quick_scan),
        ("Full Scan", full_scan),
        ("Custom Scan", custom_scan),
        ("Settings", open_settings),
        ("Security Report", lambda: messagebox.showinfo("Info", "Reports coming soon")),
        ("Quarantine", lambda: messagebox.showinfo("Info", "Quarantine coming soon"))
    ]

    for text, command in buttons:
        btn = ttk.Button(left_menu, text=text, command=command, style="Menu.TButton", width=20)
        btn.pack(pady=5, fill=X)

    content_frame = ttk.Frame(menu_frame, relief="solid", borderwidth=1)
    content_frame.pack(side=LEFT, fill=BOTH, expand=True)

    stats_frame = ttk.Frame(content_frame)
    stats_frame.pack(pady=20, padx=20, fill=X)

    ttk.Label(stats_frame, text="Last Scan: " + datetime.now().strftime("%Y-%m-%d %H:%M")).pack(anchor=W)
    ttk.Label(stats_frame, text="Files Scanned: 0").pack(anchor=W)
    ttk.Label(stats_frame, text="Threats Detected: 0").pack(anchor=W)

    def update_status():
        status_label.config(text="System Status: Secure")
        main_window.after(5000, update_status)

    update_status()

    # Start real-time protection
    start_realtime_protection()

    def on_closing():
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            stop_realtime_protection()
            main_window.quit()

    main_window.protocol("WM_DELETE_WINDOW", on_closing)


def open_register_window():
    register_window = Toplevel()
    register_window.title("Create New Account")
    register_window.geometry("500x600")
    register_window.configure(bg="#E8F0FE")
    center_window(register_window)

    style = ttk.Style()
    style.configure("Register.TLabel", font=("Arial", 11), background="#E8F0FE")
    style.configure("Register.TButton", font=("Arial", 11, "bold"))
    style.configure("RegisterTitle.TLabel", font=("Arial", 24, "bold"), foreground="#1a73e8", background="#E8F0FE")
    style.configure("RegisterFrame.TFrame", background="#E8F0FE")

    main_frame = ttk.Frame(register_window, padding="30", style="RegisterFrame.TFrame")
    main_frame.pack(fill=BOTH, expand=True)

    title_label = ttk.Label(main_frame, text="Create New Account", style="RegisterTitle.TLabel")
    title_label.pack(pady=20)

    subtitle_label = ttk.Label(main_frame, text="Please enter your information",
                               font=("Arial", 12), foreground="#5f6368", background="#E8F0FE")
    subtitle_label.pack(pady=(0, 30))

    form_frame = ttk.Frame(main_frame, style="RegisterFrame.TFrame")
    form_frame.pack(fill=BOTH, expand=True)

    username_frame = ttk.Frame(form_frame, style="RegisterFrame.TFrame")
    username_frame.pack(fill=X, pady=10)
    ttk.Label(username_frame, text="Username:", style="Register.TLabel").pack(anchor=W)
    username_entry = ttk.Entry(username_frame, width=40, font=("Arial", 11))
    username_entry.pack(fill=X, pady=(5, 0))

    password_frame = ttk.Frame(form_frame, style="RegisterFrame.TFrame")
    password_frame.pack(fill=X, pady=10)
    ttk.Label(password_frame, text="Password:", style="Register.TLabel").pack(anchor=W)
    password_entry = ttk.Entry(password_frame, show="•", width=40, font=("Arial", 11))
    password_entry.pack(fill=X, pady=(5, 0))

    password_confirm_frame = ttk.Frame(form_frame, style="RegisterFrame.TFrame")
    password_confirm_frame.pack(fill=X, pady=10)
    ttk.Label(password_confirm_frame, text="Confirm Password:", style="Register.TLabel").pack(anchor=W)
    password_confirm_entry = ttk.Entry(password_confirm_frame, show="•", width=40, font=("Arial", 11))
    password_confirm_entry.pack(fill=X, pady=(5, 0))

    def register():
        username = username_entry.get()
        password = password_entry.get()
        password_confirm = password_confirm_entry.get()

        if not username or not password or not password_confirm:
            messagebox.showerror("Error", "Please fill in all fields!")
            return

        if password != password_confirm:
            messagebox.showerror("Error", "Passwords don't match!")
            return

        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters!")
            return

        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=?", (username,))
        if c.fetchone():
            messagebox.showerror("Error", "This username is already taken!")
            conn.close()
            return

        c.execute("INSERT INTO users VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Your account has been created successfully!")
        register_window.destroy()

    button_frame = ttk.Frame(main_frame, style="RegisterFrame.TFrame")
    button_frame.pack(pady=30)

    register_btn = Button(button_frame, text="Create Account", command=register,
                          font=("Arial", 12, "bold"), width=25,
                          bg="#1a73e8", fg="white", cursor="hand2",
                          activebackground="#1557b0", activeforeground="white",
                          relief="flat", pady=10)
    register_btn.pack(pady=10)

    cancel_btn = Button(button_frame, text="Cancel", command=register_window.destroy,
                        font=("Arial", 12), width=25,
                        bg="#E8F0FE", fg="#1a73e8", cursor="hand2",
                        activebackground="#d2e3fc", activeforeground="#1a73e8",
                        relief="flat", pady=10)
    cancel_btn.pack()


def login_system():
    root = Tk()
    root.title("Antivirus Login")
    root.geometry("400x600")
    root.configure(bg="#E8F0FE")
    center_window(root)

    style = ttk.Style()
    style.configure("Login.TFrame", background="#E8F0FE")
    style.configure("Login.TLabel", font=("Arial", 11), background="#E8F0FE")
    style.configure("Login.TButton", font=("Arial", 11, "bold"), padding=10)
    style.configure("Title.TLabel", font=("Arial", 24, "bold"), foreground="#1a73e8", background="#E8F0FE")

    main_frame = ttk.Frame(root, padding="30", style="Login.TFrame")
    main_frame.pack(fill=BOTH, expand=True)

    title_label = ttk.Label(main_frame, text="Antivirus System", style="Title.TLabel")
    title_label.pack(pady=30)

    subtitle_label = ttk.Label(main_frame, text="Secure Login",
                               font=("Arial", 14), foreground="#5f6368", background="#E8F0FE")
    subtitle_label.pack(pady=(0, 30))

    create_database()

    login_frame = ttk.Frame(main_frame, style="Login.TFrame")
    login_frame.pack(fill=BOTH, expand=True)

    username_frame = ttk.Frame(login_frame, style="Login.TFrame")
    username_frame.pack(fill=X, pady=10)
    ttk.Label(username_frame, text="Username:", style="Login.TLabel").pack(anchor=W)
    ttk.Label(username_frame, text="Kullanıcı Adı:", style="Login.TLabel").pack(anchor=W)
    username_entry = ttk.Entry(username_frame, width=30, font=("Arial", 11))
    username_entry.pack(fill=X, pady=(5, 0))

    password_frame = ttk.Frame(login_frame, style="Login.TFrame")
    password_frame.pack(fill=X, pady=10)
    ttk.Label(password_frame, text="Şifre:", style="Login.TLabel").pack(anchor=W)
    password_entry = ttk.Entry(password_frame, show="•", width=30, font=("Arial", 11))
    password_entry.pack(fill=X, pady=(5, 0))

    def login():
        username = username_entry.get()
        password = password_entry.get()

        if not username or not password:
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
            return

        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=? AND password=?",
                  (username, password))

        if c.fetchone():
            messagebox.showinfo("Başarılı", "Giriş başarılı!")
            root.withdraw()
            open_main_window(username)
        else:
            messagebox.showerror("Hata", "Kullanıcı adı veya şifre hatalı!")

        conn.close()

    root.bind('<Return>', lambda event: login())

    button_frame = ttk.Frame(main_frame, style="Login.TFrame")
    button_frame.pack(pady=30)

    login_btn = Button(button_frame, text="Giriş Yap", command=login,
                       font=("Arial", 12, "bold"), width=20,
                       bg="#1a73e8", fg="white", cursor="hand2",
                       activebackground="#1557b0", activeforeground="white",
                       relief="flat", pady=8)
    login_btn.pack(pady=10)

    register_btn = Button(button_frame, text="Kayıt Ol", command=open_register_window,
                          font=("Arial", 12), width=20,
                          bg="#E8F0FE", fg="#1a73e8", cursor="hand2",
                          activebackground="#d2e3fc", activeforeground="#1a73e8",
                          relief="flat", pady=8)
    register_btn.pack()

    root.mainloop()


if __name__ == "__main__":
    login_system()

