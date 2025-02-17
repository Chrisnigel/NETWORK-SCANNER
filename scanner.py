import socket
import threading
import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedTk

# Function to scan a single IP address
def scan_ip(ip, result_text):
    try:
        # Trying to connect to common open ports (22 for SSH, 80 for HTTP, 443 for HTTPS)
        ports = [22, 80, 443]
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                result_text.insert(tk.END, f"Device found: {ip} on port {port}\n")
                result_text.yview(tk.END)
            sock.close()
    except socket.error:
        pass  # Ignore connection errors


# Function to scan a range of IP addresses in the same subnet (in a separate thread)
def scan_network(network, result_text, scan_button):
    scan_button.config(state=tk.DISABLED)
    result_text.delete(1.0, tk.END)  # Clear previous results
    threads = []

    def worker():
        # Scanning the first 254 IPs in the subnet.
        for i in range(1, 255):
            ip = f"{network}.{i}"
            thread = threading.Thread(target=scan_ip, args=(ip, result_text))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        # Re-enable the scan button after scan completes
        scan_button.config(state=tk.NORMAL)

    # Start the scanning worker in a separate thread
    threading.Thread(target=worker, daemon=True).start()


# Main function to start the GUI
def start_gui():
    # Create the main window with a futuristic dark theme
    root = ThemedTk(theme="equilux")  # Equilux is a dark theme
    root.title("Network Scanner")
    root.geometry("600x400")
    root.resizable(False, False)  # Prevent resizing to maintain a clean layout

    # Create a frame to contain the input section (network entry and scan button)
    input_frame = ttk.Frame(root, padding="20")
    input_frame.pack(pady=10)

    # Label for network input
    label = ttk.Label(input_frame, text="Enter the network to scan (e.g., 192.168.1):", font=("Helvetica", 12))
    label.grid(row=0, column=0, padx=10, pady=5)

    # Network entry field
    network_entry = ttk.Entry(input_frame, font=("Helvetica", 14), width=20)
    network_entry.grid(row=1, column=0, padx=10, pady=5)

    # Button to start scanning
    scan_button = ttk.Button(input_frame, text="Start Scanning", width=20,
                              command=lambda: scan_network(network_entry.get(), result_text, scan_button))
    scan_button.grid(row=2, column=0, padx=10, pady=10)

    # Create a frame for the results section
    result_frame = ttk.Frame(root, padding="20")
    result_frame.pack(pady=10)

    # Text area for displaying results
    result_text = tk.Text(result_frame, height=10, width=70, wrap=tk.WORD, font=("Courier", 12), bg="#333333", fg="white")
    result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Add a vertical scrollbar to the result_text area
    scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=result_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    result_text.config(yscrollcommand=scrollbar.set)

    # Run the GUI
    root.mainloop()


if __name__ == "__main__":
    start_gui()
