import tkinter as tk
import tkinter.filedialog as filedialog
import pcapScrape

def run_pcapScrape():
   # Get the current option
   current_option = drop_down_menu.cget("text")
   # Pass the current option to the main function
   pcapScrape.main(current_option)

def browseFiles():
   filename = filedialog.askopenfilename(initialdir = "/",
                               title = "Select a File",
                               filetypes = (("pcap files",
                                        "*.pcap*"),
                                       ("all files",
                                        "*.*")))
   # Update the current option
   current_option.set(filename)

def downloadReport():
   filename = filedialog.asksaveasfile(initialdir = "/",
                               title = "Download Report",
                               filetypes = (("log files",
                                        "*.log*"),
                                       ("all files",
                                        "*.*")))
   # Here you should add the code to copy the content of info.log to the selected file
   # For example:
   with open('info.log', 'r') as source:
       with open("filename.log", 'w') as target:
           target.write(source.read())

root = tk.Tk()
root.geometry("300x400")

label = tk.Label(root, text="Select a pcap file to scan")
label.config(font=("Courier", 12))
label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

options = ['data/example-tptk-attack.pcapng', 'data/example-ft.pcapng', 'data/ipv4frags.pcap', 'data/nf9-juniper-vmx.pcapng.cap', 'data/smtp.pcap', 'data/teardrop.cap', 'data/nf9-error.pcapng.cap', 'data/example-tptk-success.pcap']

# Create a variable to hold the current option
current_option = tk.StringVar()
current_option.set(options[0]) # Set the default option

# Create the drop-down menu
drop_down_menu = tk.OptionMenu(root, current_option, *options)
drop_down_menu.config(font=("Courier", 10))
drop_down_menu.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

# Create a button to browse files
button_browse = tk.Button(root, text="Browse Files", command=browseFiles)
button_browse.config(font=("Courier", 12))
button_browse.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

# Create a red "Scan" button
button = tk.Button(root, text="Scan", command=run_pcapScrape, bg='green',fg='white')
button.config(font=("Courier", 12))
button.place(relx=0.5, rely=0.6, anchor=tk.CENTER)

# Create a "Download Report" button
button_download = tk.Button(root, text="Download Report", command=downloadReport, bg='blue',fg='white')
button_download.config(font=("Courier", 12))
button_download.place(relx=0.5, rely=0.7, anchor=tk.CENTER)

root.mainloop()
