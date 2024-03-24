import re
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter import font
import webbrowser


class IOCTransformer:
    def __init__(self, master):
        self.master = master
        master.title("NeatLabs IOC Transformer Pro")
        master.geometry("1000x880")
        master.configure(bg="#e6f2ff")

        # Create custom fonts
        title_font = font.Font(family="Arial", size=24, weight="bold")
        heading_font = font.Font(family="Arial", size=12, weight="bold")
        text_font = font.Font(family="Arial", size=10)

        # Create a main frame with a scrollbar
        main_frame = ttk.Frame(master)
        main_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main_frame, bg="#e6f2ff", highlightthickness=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        content_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=content_frame, anchor="nw")

        # Title label
        title_label = ttk.Label(content_frame, text="NeatLabs IOC Transformer Pro", font=title_font, foreground="red")
        title_label.grid(row=0, column=0, columnspan=2, padx=20, pady=20)

        # IOC input section
        ioc_input_frame = ttk.LabelFrame(content_frame, text="Enter IOCs")
        ioc_input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")

        ioc_input_label = ttk.Label(ioc_input_frame, text="Enter IOCs (one per line or load from file):", font=heading_font)
        ioc_input_label.pack(anchor="w")

        self.ioc_input = scrolledtext.ScrolledText(ioc_input_frame, width=60, height=7, bg="white", fg="black", font=text_font)
        self.ioc_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        load_iocs_button = ttk.Button(ioc_input_frame, text="Load IOCs from File", command=self.load_iocs)
        load_iocs_button.pack(side=tk.LEFT, padx=5, pady=5)

        clear_iocs_button = ttk.Button(ioc_input_frame, text="Clear IOCs", command=self.clear_ioc_input)
        clear_iocs_button.pack(side=tk.LEFT, padx=5, pady=5)

        # IOC sources section
        ioc_sources_frame = ttk.LabelFrame(content_frame, text="IOC Sources")
        ioc_sources_frame.grid(row=1, column=1, padx=20, pady=10, sticky="nsew")

        ioc_sources_label = ttk.Label(ioc_sources_frame, text="Select an IOC source:", font=heading_font)
        ioc_sources_label.pack(anchor="w")

        self.ioc_sources_var = tk.StringVar(value="Select a source")
        self.ioc_sources_dropdown = ttk.Combobox(ioc_sources_frame, textvariable=self.ioc_sources_var, values=["Select a source", "AlienVault OTX", "Cisco Talos Intelligence", "Malware Bazaar", "Malshare", "ThreatConnect"], font=text_font)
        self.ioc_sources_dropdown.pack(fill=tk.X, padx=5, pady=5)
        self.ioc_sources_dropdown.bind("<<ComboboxSelected>>", self.open_ioc_source)

        # Rule description and options
        rule_options_frame = ttk.LabelFrame(content_frame, text="Rule Options")
        rule_options_frame.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")

        rule_description_label = ttk.Label(rule_options_frame, text="Rule Description:", font=heading_font)
        rule_description_label.pack(anchor="w")

        self.rule_description = scrolledtext.ScrolledText(rule_options_frame, width=120, height=4, bg="white", fg="black", font=text_font)
        self.rule_description.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.rule_description.insert(tk.END, "Select a rule type to see its description.")
        self.rule_description.configure(state="disabled")

        rule_type_label = ttk.Label(rule_options_frame, text="Select Rule Type:", font=heading_font)
        rule_type_label.pack(anchor="w")

        self.rule_type_var = tk.StringVar(value="Splunk")
        self.rule_type_dropdown = ttk.Combobox(rule_options_frame, textvariable=self.rule_type_var, values=["Splunk", "Suricata", "Yara", "Snort", "Sigma"], font=text_font)
        self.rule_type_dropdown.pack(fill=tk.X, padx=5, pady=5)
        self.rule_type_dropdown.bind("<<ComboboxSelected>>", self.update_rule_description)

        severity_label = ttk.Label(rule_options_frame, text="Severity:", font=heading_font)
        severity_label.pack(anchor="w")

        self.severity_var = tk.StringVar(value="medium")
        severity_frame = ttk.Frame(rule_options_frame)
        severity_frame.pack(fill=tk.X)

        ttk.Radiobutton(severity_frame, text="Low", variable=self.severity_var, value="low").pack(side=tk.LEFT)
        ttk.Radiobutton(severity_frame, text="Medium", variable=self.severity_var, value="medium").pack(side=tk.LEFT)
        ttk.Radiobutton(severity_frame, text="High", variable=self.severity_var, value="high").pack(side=tk.LEFT)

        # Generated rules section
        generated_rules_frame = ttk.LabelFrame(content_frame, text="Generated Rules")
        generated_rules_frame.grid(row=3, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")

        generated_rules_label = ttk.Label(generated_rules_frame, text="Generated Rules:", font=heading_font)
        generated_rules_label.pack(anchor="w")

        self.rule_output = scrolledtext.ScrolledText(generated_rules_frame, width=120, height=6, bg="white", fg="black", font=text_font)
        self.rule_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Buttons frame
        buttons_frame = ttk.Frame(content_frame)
        buttons_frame.grid(row=4, column=0, columnspan=2, padx=20, pady=10)

        generate_button = ttk.Button(buttons_frame, text="Generate Rules", command=self.generate_rules)
        generate_button.pack(side=tk.LEFT, padx=5)

        clear_button = ttk.Button(buttons_frame, text="Clear Rules", command=self.clear_rule_output)
        clear_button.pack(side=tk.LEFT, padx=5)

        copy_button = ttk.Button(buttons_frame, text="Copy Rules", command=self.copy_rules)
        copy_button.pack(side=tk.LEFT, padx=5)

        save_button = ttk.Button(buttons_frame, text="Save Rules", command=self.save_rules)
        save_button.pack(side=tk.LEFT, padx=5)

        # Rule statistics section
        statistics_frame = ttk.LabelFrame(content_frame, text="Rule Statistics")
        statistics_frame.grid(row=5, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")

        self.total_rules_label = ttk.Label(statistics_frame, text="Total Rules: 0", font=text_font)
        self.total_rules_label.pack(anchor="w")

        self.rule_type_stats_label = ttk.Label(statistics_frame, text="Rule Type Stats:", font=text_font)
        self.rule_type_stats_label.pack(anchor="w")

        # Status bar
        self.status_bar = ttk.Label(content_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=6, column=0, columnspan=2, padx=0, pady=0, sticky="we")

    def update_rule_description(self, event):
        rule_type = self.rule_type_var.get()
        description = ""

        if rule_type == "Splunk":
            description = "Splunk rules are used for searching and alerting in Splunk.\nThey are composed of Splunk search queries.\nBest suited for various data types like IP addresses, domains, and hashes."
        elif rule_type == "Suricata":
            description = "Suricata rules are used for network intrusion detection and prevention.\nThey are composed of rule header and rule options.\nBest suited for network-related data types like IP addresses and domains."
        elif rule_type == "Yara":
            description = "Yara rules are used for malware identification and classification.\nThey are composed of rule metadata, strings, and conditions.\nBest suited for file-related data types like hashes."
        elif rule_type == "Snort":
            description = "Snort rules are used for network intrusion detection and prevention.\nThey are composed of rule header and rule options.\nBest suited for network-related data types like IP addresses and domains."
        elif rule_type == "Sigma":
            description = "Sigma rules are used for generic signature format for SIEM systems.\nThey are composed of YAML-based rule format.\nBest suited for various data types like IP addresses, domains, and hashes."

        self.rule_description.configure(state="normal")
        self.rule_description.delete("1.0", tk.END)
        self.rule_description.insert(tk.END, description)
        self.rule_description.configure(state="disabled")

    def generate_rules(self):
        iocs = self.ioc_input.get("1.0", tk.END).strip().split("\n")
        rule_type = self.rule_type_var.get()
        severity = self.severity_var.get()
        rules = []
        rule_type_stats = {}

        for ioc in iocs:
            ioc = ioc.strip().replace("[", "").replace("]", "")
            if not ioc:
                continue

            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
                if rule_type == "Splunk":
                    rules.append(f"Splunk Rule: index=* {ioc} | severity={severity}")
                    rule_type_stats["Splunk"] = rule_type_stats.get("Splunk", 0) + 1
                elif rule_type == "Suricata":
                    rules.append(f"Suricata Rule: alert ip any any -> any any (msg:\"Suspicious IP\"; ip:{ioc}; severity:{severity}; sid:1000001; rev:1;)")
                    rule_type_stats["Suricata"] = rule_type_stats.get("Suricata", 0) + 1
                elif rule_type == "Snort":
                    rules.append(f"Snort Rule: alert ip any any -> {ioc} any (msg:\"Suspicious IP\"; severity:{severity}; sid:1000001; rev:1;)")
                    rule_type_stats["Snort"] = rule_type_stats.get("Snort", 0) + 1
                elif rule_type == "Sigma":
                    rules.append(f"Sigma Rule: title: Suspicious IP\ndetection:\n  selection:\n    dst_ip: '{ioc}'\n  condition: selection\n  severity: {severity}")
                    rule_type_stats["Sigma"] = rule_type_stats.get("Sigma", 0) + 1
                else:
                    messagebox.showinfo("Rule Type Recommendation", "For IP addresses, it is recommended to use Splunk, Suricata, Snort, or Sigma rule types.")

            elif re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?$", ioc):
                if rule_type == "Splunk":
                    rules.append(f"Splunk Rule: index=* {ioc} | severity={severity}")
                    rule_type_stats["Splunk"] = rule_type_stats.get("Splunk", 0) + 1
                elif rule_type == "Suricata":
                    rules.append(f"Suricata Rule: alert dns any any -> any any (msg:\"Suspicious DNS query\"; dns.query; content:\"{ioc}\"; nocase; severity:{severity}; sid:1000002; rev:1;)")
                    rule_type_stats["Suricata"] = rule_type_stats.get("Suricata", 0) + 1
                elif rule_type == "Snort":
                    rules.append(f"Snort Rule: alert udp any any -> any 53 (msg:\"Suspicious DNS query\"; content:\"{ioc}\"; nocase; severity:{severity}; sid:1000002; rev:1;)")
                    rule_type_stats["Snort"] = rule_type_stats.get("Snort", 0) + 1
                elif rule_type == "Sigma":
                    rules.append(f"Sigma Rule: title: Suspicious DNS Query\ndetection:\n  selection:\n    query: '*{ioc}*'\n  condition: selection\n  severity: {severity}")
                    rule_type_stats["Sigma"] = rule_type_stats.get("Sigma", 0) + 1
                else:
                    messagebox.showinfo("Rule Type Recommendation", "For domain names, it is recommended to use Splunk, Suricata, Snort, or Sigma rule types.")

            elif re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
                if rule_type == "Yara":
                    rules.append(f"Yara Rule: rule suspicious_hash {{strings: $hash = \"{ioc}\" condition: $hash}}")
                    rule_type_stats["Yara"] = rule_type_stats.get("Yara", 0) + 1
                elif rule_type == "Sigma":
                    rules.append(f"Sigma Rule: title: Suspicious Hash\ndetection:\n  selection:\n    hash: '{ioc}'\n  condition: selection\n  severity: {severity}")
                    rule_type_stats["Sigma"] = rule_type_stats.get("Sigma", 0) + 1
                else:
                    messagebox.showinfo("Rule Type Recommendation", "For hashes, it is recommended to use Yara or Sigma rule types.")
            else:
                messagebox.showinfo("Invalid IOC", f"Invalid IOC: {ioc}")

        self.rule_output.delete("1.0", tk.END)
        self.rule_output.insert(tk.END, "\n".join(rules))
        self.status_bar.config(text="Rules generated successfully.")

        self.total_rules_label.config(text=f"Total Rules: {len(rules)}")
        rule_type_stats_text = "\n".join([f"{rule_type}: {count}" for rule_type, count in rule_type_stats.items()])
        self.rule_type_stats_label.config(text=f"Rule Type Stats:\n{rule_type_stats_text}")

    def clear_ioc_input(self):
        self.ioc_input.delete("1.0", tk.END)
        self.status_bar.config(text="IOCs cleared.")

    def clear_rule_output(self):
        self.rule_output.delete("1.0", tk.END)
        self.status_bar.config(text="Rules cleared.")

    def copy_rules(self):
        self.master.clipboard_clear()
        self.master.clipboard_append(self.rule_output.get("1.0", tk.END))
        self.status_bar.config(text="Rules copied to clipboard.")

    def save_rules(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.rule_output.get("1.0", tk.END))
            self.status_bar.config(text=f"Rules saved to {file_path}")

    def load_iocs(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r") as file:
                iocs = file.read()
                self.ioc_input.delete("1.0", tk.END)
                self.ioc_input.insert(tk.END, iocs)
            self.status_bar.config(text=f"IOCs loaded from {file_path}")

    def open_ioc_source(self, event):
        selected_source = self.ioc_sources_var.get()
        if selected_source == "AlienVault OTX":
            webbrowser.open("https://otx.alienvault.com/")
        elif selected_source == "Cisco Talos Intelligence":
            webbrowser.open("https://talosintelligence.com/")
        elif selected_source == "Malware Bazaar":
            webbrowser.open("https://bazaar.abuse.ch/")
        elif selected_source == "Malshare":
            webbrowser.open("https://malshare.com/")
        elif selected_source == "ThreatConnect":
            webbrowser.open("https://threatconnect.com/")


if __name__ == "__main__":
    root = tk.Tk()
    transformer = IOCTransformer(root)
    root.mainloop()