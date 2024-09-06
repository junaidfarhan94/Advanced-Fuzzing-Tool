import requests
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import scrolledtext
import threading
import csv
import json
import urllib.parse
import random
import time
from bs4 import BeautifulSoup

# Global variables
fuzzing_results = []
fuzzing_active = True
request_count = 0
timeout = 5

def update_log(request_no, domain, path, status_code, length, error=None, final_url=None):
    """
    Update the log window with the provided details.
    """
    if not fuzzing_active:
        return

    color = {
        200: "#4CAF50",  # Green for valid response
        404: "#FFFFFF",  # White for 404 errors
        403: "#FF0000",  # Red for 403 errors
    }.get(status_code, "#FFFFFF")  # White for other status codes

    error_message = f" | Error: {error}" if error else ""
    final_url_str = f" | Redirected to: {final_url}" if final_url else ""
    log_message = f"+ {domain}/{path} (CODE:{status_code}|SIZE:{length}){error_message}{final_url_str}"
    log_window.config(state=tk.NORMAL)
    log_window.insert(tk.END, f"{log_message}\n", "status")
    log_window.tag_config("status", foreground=color)
    log_window.yview(tk.END)
    log_window.config(state=tk.DISABLED)

def send_request(url, path, user_agent):
    """
    Send HTTP request and process response.
    """
    global request_count
    full_url = f"{url}/{path}"
    request_count += 1
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(full_url, timeout=timeout, headers=headers)
        status_code = response.status_code
        length = len(response.content)
        final_url = response.url if response.history else None
        if status_code == 403:
            # Attempt bypass strategies
            response = bypass_403(url, path, headers)
            status_code = response.status_code
            length = len(response.content)
            final_url = response.url if response.history else None
        update_log(request_count, url.split('/')[2], path, status_code, length, final_url=final_url)
        if status_code == 200:
            fuzzing_results.append(full_url)
            update_log(request_count, url.split('/')[2], path, f"Found: {status_code}", length)
    except requests.RequestException as e:
        update_log(request_count, url.split('/')[2], path, "Error", 0, str(e))

def bypass_403(url, path, headers):
    """
    Attempt to bypass 403 restrictions using common techniques.
    """
    # Example bypass strategies
    headers['Referer'] = url
    headers['X-Forwarded-For'] = '8.8.8.8'
    response = requests.get(f"{url}/{path}", timeout=timeout, headers=headers)
    return response

def fuzz_domain(url, wordlist, attack_type, threads):
    """
    Fuzz the given domain or subdomain using a wordlist with multithreading.
    """
    global fuzzing_active
    fuzzing_results.clear()

    with open(wordlist, "r") as file:
        paths = [line.strip() for line in file]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:90.0) Gecko/20100101 Firefox/90.0",
        # Add more user agents if needed
    ]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for path in paths:
            user_agent = random.choice(user_agents)
            executor.submit(send_request, url, path, user_agent)
            time.sleep(1)  # Add delay to avoid rate limiting

    if fuzzing_results:
        result_str = "\n".join(fuzzing_results)
        messagebox.showinfo("Fuzzing Complete", f"Found URLs:\n{result_str}")
    else:
        messagebox.showinfo("Fuzzing Complete", "No valid paths found.")

def start_fuzzing():
    """
    Start the fuzzing process (triggered by GUI).
    """
    global fuzzing_active, timeout
    url = entry_url.get()
    wordlist = entry_wordlist.get()
    attack_type = combo_attack_type.get()
    threads = int(entry_threads.get())
    timeout = int(entry_timeout.get())

    if not url or not wordlist:
        messagebox.showerror("Error", "URL and Wordlist are required!")
        return

    fuzzing_active = True
    fuzz_thread = threading.Thread(target=fuzz_domain, args=(url, wordlist, attack_type, threads))
    fuzz_thread.start()

def stop_fuzzing():
    """
    Stop the fuzzing process (triggered by GUI).
    """
    global fuzzing_active
    fuzzing_active = False
    messagebox.showinfo("Fuzzing Stopped", "Fuzzing process has been stopped.")

def select_wordlist():
    """
    Open file dialog to select a wordlist.
    """
    wordlist_path = filedialog.askopenfilename()
    entry_wordlist.delete(0, tk.END)
    entry_wordlist.insert(0, wordlist_path)

def export_results():
    """
    Export fuzzing results to a file.
    """
    if not fuzzing_results:
        messagebox.showerror("Error", "No results to export!")
        return

    filetypes = [("CSV files", "*.csv"), ("JSON files", "*.json")]
    file_path = filedialog.asksaveasfilename(filetypes=filetypes, defaultextension=filetypes)

    if file_path.endswith('.csv'):
        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["URL"])
            for result in fuzzing_results:
                writer.writerow([result])
    elif file_path.endswith('.json'):
        with open(file_path, 'w') as jsonfile:
            json.dump(fuzzing_results, jsonfile, indent=4)

def url_decoder(url):
    """
    Decode URL-encoded characters.
    """
    return urllib.parse.unquote(url)

def parameter_finder(url):
    """
    Find parameters in URL for advanced fuzzing.
    """
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    params = [param.get('name') for param in soup.find_all(['input', 'textarea', 'select'])]
    return list(set(params))

def subdomain_finder(domain):
    """
    Find subdomains for a given domain.
    """
    subdomains = ["api", "www", "mail", "ftp"]  # Example subdomains
    found_subdomains = []
    for sub in subdomains:
        subdomain = f"http://{sub}.{domain}"
        try:
            response = requests.get(subdomain, timeout=timeout)
            if response.status_code == 200:
                found_subdomains.append(subdomain)
        except requests.RequestException:
            continue
    return found_subdomains

def configure_gui():
    """
    Configure the GUI elements.
    """
    log_window.config(font=("Helvetica", 12))
    signature.config(font=("Helvetica", 12))
    log_frame.pack(pady=10)

# GUI Setup using Tkinter
root = tk.Tk()
root.title("Fuzzing Tool")
root.geometry("1000x900")  # Set initial size
root.configure(bg="#1e1e1e")  # Dark background

# Tabs
tab_control = ttk.Notebook(root)
tab_target = ttk.Frame(tab_control)
tab_payloads = ttk.Frame(tab_control)
tab_options = ttk.Frame(tab_control)

tab_control.add(tab_target, text='Target')
tab_control.add(tab_payloads, text='Payloads')
tab_control.add(tab_options, text='Options')
tab_control.pack(expand=1, fill='both')

# Target Tab
ttk.Label(tab_target, text="Target URL:", background="#1e1e1e", foreground="#E0E0E0").grid(row=0, column=0, padx=10, pady=10)
entry_url = ttk.Entry(tab_target, width=60)
entry_url.grid(row=0, column=1, padx=10, pady=10)

# Payloads Tab
ttk.Label(tab_payloads, text="Wordlist:", background="#1e1e1e", foreground="#E0E0E0").grid(row=0, column=0, padx=10, pady=10)
entry_wordlist = ttk.Entry(tab_payloads, width=60)
entry_wordlist.grid(row=0, column=1, padx=10, pady=10)
ttk.Button(tab_payloads, text="Browse", command=select_wordlist).grid(row=0, column=2, padx=10, pady=10)

# Options Tab
ttk.Label(tab_options, text="Attack Type:", background="#1e1e1e", foreground="#E0E0E0").grid(row=0, column=0, padx=10, pady=10)
combo_attack_type = ttk.Combobox(tab_options, values=["Simple", "Advanced"])
combo_attack_type.grid(row=0, column=1, padx=10, pady=10)
combo_attack_type.set("Simple")

ttk.Label(tab_options, text="Threads:", background="#1e1e1e", foreground="#E0E0E0").grid(row=1, column=0, padx=10, pady=10)
entry_threads = ttk.Entry(tab_options, width=10)
entry_threads.grid(row=1, column=1, padx=10, pady=10)
entry_threads.insert(0, "10")

ttk.Label(tab_options, text="Timeout (s):", background="#1e1e1e", foreground="#E0E0E0").grid(row=2, column=0, padx=10, pady=10)
entry_timeout = ttk.Entry(tab_options, width=10)
entry_timeout.grid(row=2, column=1, padx=10, pady=10)
entry_timeout.insert(0, "5")

# Parameter Finder
ttk.Button(tab_options, text="Find Parameters", command=lambda: find_parameters(entry_url.get())).grid(row=3, column=0, padx=10, pady=10)

# Subdomain Finder
ttk.Button(tab_options, text="Find Subdomains", command=lambda: find_subdomains(entry_url.get())).grid(row=3, column=1, padx=10, pady=10)

# Fuzzing Controls
ttk.Button(tab_target, text="Start Fuzzing", command=start_fuzzing).grid(row=1, column=1, padx=10, pady=10)
ttk.Button(tab_target, text="Stop Fuzzing", command=stop_fuzzing).grid(row=1, column=2, padx=10, pady=10)
ttk.Button(tab_target, text="Export Results", command=export_results).grid(row=1, column=3, padx=10, pady=10)

# Log Window
log_frame = ttk.Frame(root, padding=10)
log_frame.pack(expand=True, fill='both')
log_window = scrolledtext.ScrolledText(log_frame, height=20, width=120, state=tk.DISABLED, wrap=tk.WORD, bg="#1e1e1e", fg="#E0E0E0", font=("Helvetica", 12))  # Medium font
log_window.pack(expand=True, fill='both')

# Signature
signature = ttk.Label(root, text="Tool created by Junaid Farhan\nInstagram: /jdf_000", background="#1e1e1e", foreground="#E0E0E0", font=("Helvetica", 12))
signature.pack(side=tk.BOTTOM, pady=10)

# Configure log colors
def configure_log_colors():
    log_window.tag_configure("status_200", foreground="#4CAF50")  # Green for valid response
    log_window.tag_configure("status_error", foreground="#FFFFFF")  # White for errors
    log_window.tag_configure("status_default", foreground="#FFFFFF")  # White for other status codes

configure_log_colors()

def find_parameters(url):
    """
    Find parameters in the URL and display them.
    """
    params = parameter_finder(url)
    params_str = "\n".join(params)
    messagebox.showinfo("Parameters Found", f"Parameters:\n{params_str}")

def find_subdomains(domain):
    """
    Find subdomains and display them.
    """
    subdomains = subdomain_finder(domain)
    subdomains_str = "\n".join(subdomains)
    messagebox.showinfo("Subdomains Found", f"Subdomains:\n{subdomains_str}")

# Main loop
configure_gui()
root.mainloop()
