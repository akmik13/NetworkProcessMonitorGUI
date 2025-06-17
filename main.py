import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import time
import socket
import json
import os

class NetworkProcessMonitorGUI:
    SETTINGS_FILE = "window_settings.json"
    def __init__(self, root):
        self.root = root
        self.root.title("Network Process Monitor GUI")
        self.monitoring = False
        self.selected_pid = None
        self.monitor_thread = None
        self.paned = None
        self.tree = None
        self.log_text = None
        self.restore_window_settings()
        self.create_widgets()
        self.populate_processes()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        self.root.configure(bg="#23272e")
        search_frame = tk.Frame(self.root, bg="#23272e")
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(search_frame, text="Filter:", fg="#e0e0e0", bg="#23272e").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', lambda *args: self.populate_processes())
        filter_entry = tk.Entry(search_frame, textvariable=self.filter_var, width=30, bg="#2c313a", fg="#e0e0e0", insertbackground="#e0e0e0")
        filter_entry.pack(side=tk.LEFT, padx=5)
        refresh_btn = tk.Button(search_frame, text="Refresh", command=self.populate_processes, bg="#444857", fg="#e0e0e0", activebackground="#3a3f4b", activeforeground="#ffffff")
        refresh_btn.pack(side=tk.LEFT, padx=5)

        self.paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("#", "PID", "Process Name", "Path")
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#23272e", foreground="#e0e0e0", fieldbackground="#23272e", rowheight=28)
        style.configure("Treeview.Heading", background="#2c313a", foreground="#e0e0e0", font=(None, 10, 'bold'))
        style.map("Treeview", background=[('selected', '#444857')], foreground=[('selected', '#ffffff')])
        style.configure("TButton", background="#444857", foreground="#e0e0e0")
        style.map("TButton", background=[('active', '#3a3f4b')], foreground=[('active', '#ffffff')])
        self.tree = ttk.Treeview(self.paned, columns=columns, show="headings", height=15, selectmode="extended")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180 if col=="Path" else 100, anchor=tk.CENTER)
        self.tree.bind("<ButtonRelease-1>", self.on_process_select)
        self.paned.add(self.tree, weight=3)

        btn_frame = tk.Frame(self.root, bg="#23272e")
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        self.start_btn = tk.Button(btn_frame, text="Start Scan", command=self.start_scan, state=tk.DISABLED, bg="#444857", fg="#e0e0e0", activebackground="#3a3f4b", activeforeground="#ffffff")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED, bg="#444857", fg="#e0e0e0", activebackground="#3a3f4b", activeforeground="#ffffff")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        terminate_btn = tk.Button(btn_frame, text="Terminate Process", command=self.terminate_process, bg="#444857", fg="#e0e0e0", activebackground="#3a3f4b", activeforeground="#ffffff")
        terminate_btn.pack(side=tk.LEFT, padx=5)

        log_frame = tk.LabelFrame(self.paned, text="Network Activity Log", bg="#23272e", fg="#e0e0e0")
        self.log_text = tk.Text(log_frame, height=10, state=tk.DISABLED, bg="#2c313a", fg="#e0e0e0", insertbackground="#e0e0e0")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.paned.add(log_frame, weight=2)
        self.restore_paned_sizes()

    def populate_processes(self):
        filter_text = self.filter_var.get().lower()
        for row in self.tree.get_children():
            self.tree.delete(row)
        for idx, proc in enumerate(psutil.process_iter(['pid', 'name', 'exe'])):
            try:
                name = proc.info['name'] or ''
                path = proc.info['exe'] or ''
                if filter_text and filter_text not in name.lower() and filter_text not in path.lower():
                    continue
                self.tree.insert('', 'end', values=(idx+1, proc.info['pid'], name, path))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self.start_btn.config(state=tk.DISABLED)
        self.selected_pid = None
        self.auto_select_by_name = tk.BooleanVar(value=True)

    def on_process_select(self, event):
        selected = self.tree.selection()
        if selected:
            if self.auto_select_by_name.get() and len(selected) == 1:
                name = self.tree.item(selected[0])['values'][2]
                # Автоматически выделить все строки с этим именем
                for iid in self.tree.get_children():
                    if self.tree.item(iid)['values'][2] == name:
                        self.tree.selection_add(iid)
                # Собрать все PID с этим именем
                names = {name}
            else:
                # Ручное выделение
                names = set(self.tree.item(iid)['values'][2] for iid in selected)
            pids = [proc.info['pid'] for proc in psutil.process_iter(['pid', 'name']) if proc.info['name'] in names]
            self.selected_pids = pids
            self.start_btn.config(state=tk.NORMAL if not self.monitoring else tk.DISABLED)
        else:
            self.selected_pids = []
            self.start_btn.config(state=tk.DISABLED)

    def start_scan(self):
        if not self.selected_pids:
            messagebox.showwarning("No process selected", "Please select one or more processes to monitor.")
            return
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, f"Monitoring PIDs {', '.join(map(str, self.selected_pids))}...\n")
        self.log_text.config(state=tk.DISABLED)
        self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitor_thread.start()

    def stop_scan(self):
        self.monitoring = False
        self.stop_btn.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.NORMAL if self.selected_pid else tk.DISABLED)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, "Stopped monitoring.\n")
        self.log_text.config(state=tk.DISABLED)

    def terminate_process(self):
        if not self.selected_pids:
            messagebox.showwarning("No process selected", "Please select one or more processes to terminate.")
            return
        for pid in self.selected_pids:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=3)
                messagebox.showinfo("Terminated", f"Process {pid} terminated.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to terminate process {pid}: {e}")
        self.populate_processes()

    def monitor_network(self):
        prev_conns = dict()
        ip_logs = dict()  # process name -> set of IPs
        while self.monitoring:
            for pid in self.selected_pids:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    conns = proc.connections(kind='inet')
                    new_conns = set()
                    new_ips = set()
                    for conn in conns:
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                        status = conn.status
                        new_conns.add((laddr, raddr, status))
                        if conn.raddr:
                            new_ips.add(conn.raddr.ip)
                    added = new_conns - prev_conns.get(pid, set())
                    removed = prev_conns.get(pid, set()) - new_conns
                    if added or removed:
                        self.log_text.config(state=tk.NORMAL)
                        for conn in added:
                            self.log_text.insert(tk.END, f"[PID {pid}] [NEW] {conn[0]} -> {conn[1]} [{conn[2]}]\n")
                        for conn in removed:
                            self.log_text.insert(tk.END, f"[PID {pid}] [CLOSED] {conn[0]} -> {conn[1]} [{conn[2]}]\n")
                        self.log_text.see(tk.END)
                        self.log_text.config(state=tk.DISABLED)
                    # Логирование новых IP-адресов
                    if name not in ip_logs:
                        ip_logs[name] = set()
                        # Прочитать уже записанные IP из файла
                        log_path = f"{name}.log"
                        if os.path.exists(log_path):
                            with open(log_path, "r") as f:
                                for line in f:
                                    ip_logs[name].add(line.strip())
                    new_unique_ips = new_ips - ip_logs[name]
                    if new_unique_ips:
                        with open(f"{name}.log", "a") as f:
                            for ip in new_unique_ips:
                                f.write(ip + "\n")
                        ip_logs[name].update(new_unique_ips)
                    prev_conns[pid] = new_conns
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, f"[PID {pid}] Process ended or access denied.\n")
                    self.log_text.config(state=tk.DISABLED)
                    prev_conns.pop(pid, None)
            time.sleep(1)

    def on_close(self):
        self.save_window_settings()
        self.root.destroy()

    def save_window_settings(self):
        try:
            geom = self.root.geometry()
            paned_sizes = self.paned.sashpos(0) if self.paned else None
            settings = {
                "geometry": geom,
                "paned_size": paned_sizes
            }
            with open(self.SETTINGS_FILE, "w") as f:
                json.dump(settings, f)
        except Exception:
            pass

    def restore_window_settings(self):
        if os.path.exists(self.SETTINGS_FILE):
            try:
                with open(self.SETTINGS_FILE, "r") as f:
                    settings = json.load(f)
                if "geometry" in settings:
                    self.root.geometry(settings["geometry"])
                self._restored_paned_size = settings.get("paned_size")
            except Exception:
                self._restored_paned_size = None
        else:
            self._restored_paned_size = None

    def restore_paned_sizes(self):
        if hasattr(self, "_restored_paned_size") and self._restored_paned_size is not None:
            try:
                self.paned.sashpos(0, self._restored_paned_size)
            except Exception:
                pass

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkProcessMonitorGUI(root)
    root.mainloop()