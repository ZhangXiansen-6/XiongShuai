import os
import hashlib
import psutil
import time
import tempfile
import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog
from threading import Thread

# 已知的病毒文件哈希列表 (示例)
KNOWN_VIRUS_HASHES = {
    'eicar_test_file': '44d88612fea8a8f36de82e1278abb02f'
}

# 已知的恶意文件签名示例
KNOWN_MALICIOUS_SIGNATURES = {
    "test_file_malware": b"This is a test file for antivirus detection. DO NOT open!"
}


# 特征扫描功能
def calculate_file_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_file_signature(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            for sig_name, signature in KNOWN_MALICIOUS_SIGNATURES.items():
                if signature in file_data:
                    display_output(f"[警告] 检测到已知恶意签名([Warning] Known malicious signature detected) '{sig_name}' 在文件(In the file): {file_path}")
                    return True
        display_output(f"[安全] 文件签名检测无异常（[Security] No anomalies in document signature detection）: {file_path}")
        return False
    except Exception as e:
        display_output(f"[错误] 无法读取文件 {file_path}: {e}")
        return False


def scan_file(file_path):
    try:
        file_hash = calculate_file_hash(file_path)
        virus_name = next((name for name, hash_val in KNOWN_VIRUS_HASHES.items() if hash_val == file_hash), None)
        if virus_name:
            display_output(f"[警告] 检测到病毒文件（[Warning] Virus file detected）: {file_path} (病毒名称（Virus name）: {virus_name}, 哈希值（hash value）: {file_hash})")
            return True
        else:
            display_output(f"[安全] 文件哈希检测无异常（[Security] File hash detection without exception）: {file_path}")

        if check_file_signature(file_path):
            return True
        return False
    except PermissionError:
        display_output(f"[权限错误] 无法访问文件（[Permission error] Unable to access file.）: {file_path}")
    except FileNotFoundError:
        display_output(f"[未找到] 文件不存在: {file_path}")
    except Exception as e:
        display_output(f"[错误] 扫描文件 {file_path} 时发生错误: {e}")
    return False


def scan_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path)






# 行为监控功能
#通过行为监控来检测进程对文件的不断的写入操作，
#模拟一个潜在的恶意进程对 .dll 文件的修改，并显示监控日志。
def monitor_process_behavior(pid):
    try:
        process = psutil.Process(pid)  #进程获取！！！
        display_output(f"[监控] 开始监控进程([Monitor] Start monitoring process): {process.name()} (PID: {pid})")

        start_time = time.time()
        while process.is_running() and (time.time() - start_time) < 10:
            display_output(f"[调试] 正在监控进程([Debugging] Process being monitored) {pid}...")

            open_files = process.open_files()
            if open_files:
                for file in open_files:
                    display_output(f"[调试] 当前打开文件([Debugging] Currently open file): {file.path}")
                    if file.path.endswith(('.exe', '.dll')):
                        display_output(f"[警告] 检测到进程([Warning] Process detected) {pid} 正在修改可疑文件Suspicious files are being modified: {file.path}")
            else:
                display_output(f"[调试] 未检测到打开的文件")

            time.sleep(2)
    except psutil.NoSuchProcess:
        display_output(f"[错误] 进程 {pid} 不存在或已终止")
    except Exception as e:
        display_output(f"[错误] 监控进程 {pid} 时发生错误: {e}")


def behavior_monitor_test():
    with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as temp_file: #1.创建临时 .dll 文件
        temp_file_path = temp_file.name
        display_output(f"[调试] 创建了测试文件([Debugging] Test file created): {temp_file_path}")

    with open(temp_file_path, 'w') as test_file:  #2.启动Python 进程不断写入操作 .dll 文件，以模拟可疑的文件写操作
        display_output("[监控] 开始模拟可疑文件写操作([Monitor] Start simulating a suspicious file write operation)")

        pid = psutil.Process().pid
        monitor_thread = Thread(target=monitor_process_behavior, args=(pid,))  #3.监控进程行为
        monitor_thread.start()

        end_time = time.time() + 10
        while time.time() < end_time:
            test_file.write("test")
            test_file.flush()
            time.sleep(1)

        display_output("[调试] 测试进程已结束([Debugging] The test process has ended)")


# GUI应用
def start_scan():
    output_text.delete('1.0', tk.END)
    directory = filedialog.askdirectory()
    if directory:
        scan_thread = Thread(target=scan_directory, args=(directory,))
        scan_thread.start()


def start_behavior_monitor():
    output_text.delete('1.0', tk.END)
    monitor_thread = Thread(target=behavior_monitor_test)
    monitor_thread.start()


def display_output(text):
    if "[警告]" in text:
        output_text.insert(tk.END, text + '\n', 'warning')
    else:
        output_text.insert(tk.END, text + '\n')
    output_text.see(tk.END)


# 创建界面
root = tk.Tk()
root.title("Antivirus Software GUI")

frame = tk.Frame(root)
frame.pack(pady=10)

output_text = scrolledtext.ScrolledText(root, width=120, height=30)
output_text.pack(pady=10)

scan_button = tk.Button(frame, text="Feature Scan", command=start_scan, width=20)
scan_button.grid(row=0, column=0, padx=10)

monitor_button = tk.Button(frame, text="Behavior Monitoring", command=start_behavior_monitor, width=20)
monitor_button.grid(row=0, column=1, padx=10)

# 添加红色字体样式，用于警告信息
output_text.tag_configure('warning', foreground='red')

root.mainloop()
