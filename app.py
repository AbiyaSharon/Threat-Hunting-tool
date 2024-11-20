import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
from datetime import datetime
import os
from scapy.all import sniff
import hashlib

class ThreatHuntingToolApp:
    malware_signatures = {
        "e99a18c428cb38d5f260853678922e03": "Malware A",
        "d41d8cd98f00b204e9800998ecf8427e": "Malware B",
        "098f6bcd4621d373cade4e832627b4f6": "Malware C"
    }
    
    def __init__(self, root):
        self.root = root
        self.root.title("AI-based Threat Hunting Tool")
        self.root.configure(bg='black')

        # Load the background image
        self.background_image = tk.PhotoImage(file="background.png")  # Replace with your image file

        # Interface frame
        self.interface_frame = tk.Frame(root, bg='black')
        self.interface_frame.pack(fill='both', expand=True)

        # Background image
        self.canvas = tk.Canvas(self.interface_frame, width=self.background_image.width(), height=self.background_image.height(), bg='black', highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        self.canvas.create_image(0, 0, anchor='nw', image=self.background_image)

        # Start Button
        self.start_button = ttk.Button(self.interface_frame, text="Start", command=self.open_tool_interface, style='Radium.TButton')
        self.start_button.place(relx=0.5, rely=0.5, anchor='center')

        # Running Processes Text Widget
        self.process_text = tk.Text(self.interface_frame, bg='black', fg='#00FF00', state='disabled')
        self.process_text.pack(fill='both', expand=True, pady=20)

    def open_tool_interface(self):
        self.interface_frame.destroy()  # Destroy the initial frame

        # Interface frame for analysis tools
        self.analysis_frame = tk.Frame(self.root, bg='black')
        self.analysis_frame.pack(fill='both', expand=True)

        # Create subframes
        self.button_frame = tk.Frame(self.analysis_frame, bg='black')
        self.button_frame.pack(side='left', fill='both', expand=True, padx=20, pady=20)
        self.result_frame = tk.Frame(self.analysis_frame, bg='black')
        self.result_frame.pack(side='right', fill='both', expand=True, padx=20, pady=20)

        # Create buttons for analysis tools
        self.create_analysis_buttons()

        # Running Processes Label
        self.process_label = ttk.Label(self.result_frame, text="Running Processes", background='black', foreground='#00FF00', font=('Helvetica', 12, 'bold'))
        self.process_label.pack(pady=10, padx=10, anchor='w')

        # Start updating the running processes
        self.update_running_processes()

    def create_analysis_buttons(self):
        ttk.Button(self.button_frame, text="OSQuery Analysis", command=self.osquery_analysis, style='Radium.TButton').pack(pady=10, fill='x')
        ttk.Button(self.button_frame, text="Threat Hunting", command=self.threat_hunting_analysis, style='Radium.TButton').pack(pady=10, fill='x')
        ttk.Button(self.button_frame, text="Network analysis", command=self.ip_analysis, style='Radium.TButton').pack(pady=10, fill='x')
        ttk.Button(self.button_frame, text="Wireshark Analysis", command=self.wireshark_analysis, style='Radium.TButton').pack(pady=10, fill='x')
        ttk.Button(self.button_frame, text="Generate Report", command=self.generate_report, style='Radium.TButton').pack(pady=10, fill='x')

    def osquery_analysis(self):
        # Placeholder for OSQuery analysis
        output_text = "Performing OSQuery analysis...\n"
    
        # Get OS information
        os_info = f"Operating System: {os.name}\n"
        os_info += f"Platform: {os.sys.platform}\n"
        os_info += f"OS Release: {os.uname().release}\n"
        os_info += f"OS Version: {os.uname().version}\n"
        os_info += f"Architecture: {os.uname().machine}\n"

        output_text += os_info
    
        # Display output
        self.display_output(output_text)

    def threat_hunting_analysis(self):
        # Ask user to select a directory for malware scanning
        directory = filedialog.askdirectory()
        if not directory:
            messagebox.showerror("Error", "Please select a directory")
            return

        output_text = f"Performing threat hunting analysis on directory: {directory}\n"
        output_text += self.perform_malware_scan(directory)

        # Display the background analysis process
        self.display_output(output_text)

    def perform_malware_scan(self, directory):
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = self.calculate_md5(file_path)
                if file_hash in self.malware_signatures:
                    results.append(f"Malware detected: {self.malware_signatures[file_hash]} in file {file_path}\n")
        if not results:
            return "No malware detected.\n"
        return "".join(results)

    def calculate_md5(self, file_path):
        """Calculate the MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
        except Exception as e:
            return None
        return hash_md5.hexdigest()

    def ip_analysis(self):
        # Placeholder for Network analysis
        output_text = "Performing Network analysis...\n"
    
        # Get IP addresses and MAC addresses
        ip_mac_addresses = self.get_ip_mac_addresses()
    
        # Display IP addresses and MAC addresses
        output_text += "IP addresses and MAC addresses:\n"
        for ip, mac in ip_mac_addresses:
            output_text += f"IP: {ip}, MAC: {mac}\n"
    
        self.display_output(output_text)

    def get_ip_mac_addresses(self):
        # Placeholder function to get IP and MAC addresses
        # Here, you can use any method to retrieve IP and MAC addresses
        # For demonstration purposes, let's assume we are fetching them from the system
        ip_mac_addresses = []
        for interface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                if snic.family == psutil.AF_INET:
                    ip_mac_addresses.append((snic.address, snic.address))
                elif snic.family == psutil.AF_LINK:
                    ip_mac_addresses[-1] = (ip_mac_addresses[-1][0], snic.address)
        return ip_mac_addresses


    def wireshark_analysis(self):
        # Placeholder for Wireshark analysis
        output_text = "Performing Wireshark analysis...\n"
        # Example: Analyze network traffic using AI algorithms
        # Placeholder: Replace this with your actual implementation
        output_text += "Network traffic analyzed: (placeholder)\n"
        self.display_output(output_text)

        # Capture packets using scapy
        packets = sniff(count=10)  # Capture 10 packets
        for packet in packets:
            output_text += str(packet) + "\n"  # Add each packet to the output text

        # Display the captured packets
        self.display_output(output_text)

    def generate_report(self):
        # Collect analyzed data
        osquery_data = "Placeholder for OSQuery analysis data\n"
        wireshark_data = "Placeholder for Wireshark analysis data\n"
        ip_analysis_data = "Placeholder for Network analysis data\n"

        # Combine all data
        report_data = f"OSQuery Analysis Data:\n{osquery_data}\nWireshark Captured Packets:\n{wireshark_data}\nNetwork analysis Data:\n{ip_analysis_data}"

        # Save report to a file with date and time
        now = datetime.now()
        report_file_name = f"Threat_Report_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        with open(report_file_name, 'w') as report_file:
            report_file.write(report_data)

        messagebox.showinfo("Report Generated", f"Report '{report_file_name}' generated successfully.")

        # Display the report content
        self.display_output(report_data)

    def display_output(self, output_text):
        output_window = tk.Toplevel(self.root)
        output_window.title("Analysis Output")
        output_window.configure(bg='black')

        output_label = ttk.Label(output_window, text="Analysis Output", background='black', foreground='#00FF00', font=('Helvetica', 12, 'bold'))
        output_label.pack(pady=10)

        output_text_widget = tk.Text(output_window, bg='black', fg='#00FF00')
        output_text_widget.pack(fill='both', expand=True)
        output_text_widget.insert('end', output_text)
        output_text_widget.config(state='disabled')

    def update_running_processes(self):
        processes = []
        for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
            processes.append(proc.info)
            self.process_text.config(state='normal')
        self.process_text.delete(1.0, tk.END)
        for proc in processes:
            self.process_text.insert('end', f"{proc}\n")
        self.process_text.config(state='disabled')

        # Schedule the next update in 5 seconds
        self.root.after(5000, self.update_running_processes)

    def show_processes(self):
        processes = []
        for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
            processes.append(proc.info)        
        process_window = tk.Toplevel(self.root)
        process_window.title("Running Processes")
        process_window.configure(bg='#2e3f4f')
        text = tk.Text(process_window, bg='#2e3f4f', fg='white')
        text.pack(fill='both', expand=True)
        for proc in processes:
            text.insert('end', f"{proc}\n")
        text.config(state='disabled')


def main():
    root = tk.Tk()
    app = ThreatHuntingToolApp(root)

    # Define a custom style for buttons
    style = ttk.Style()
    style.configure('Radium.TButton', foreground='black', background='#00FF00', font=('Helvetica', 12, 'bold'))

    root.mainloop()

if __name__ == "__main__":
    main()

