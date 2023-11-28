import tkinter as tk
import tkinter.filedialog as filedialog
import pcapScrape
import shutil
import os
import atexit
import glob 

def delete_log_files():
   # Get a list of all log files
   log_files = glob.glob('*.log')
   # Delete each log file
   for log_file in log_files:
       os.remove(log_file)

def run_pcapScrape():
   # Hide 
  no_error_label.place_forget()
   # Hide error
  error_label.place_forget()
   # Hide download
  button_download.place_forget()
   # Get the current option
  current_option = drop_down_menu.cget("text")
  # Clear the info.log file
  with open('info.log', 'w'):
      pass
  with open('security.log', 'w'):
      pass
  with open('error.log', 'w'):
      pass

  # Pass the current option to the main function
  pcapScrape.main(current_option)
  # Show the "Download Report" button
  if os.path.getsize('suspicious_packets.log') > 0:
     # Show the error message
     error_label.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
     # Show the "Download Report" button
     button_download.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
  else:
     no_error_label.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
     

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
  filename = filedialog.asksaveasfilename(initialdir = "/",
                             title = "Download Report",
                             filetypes = (("log files",
                                     "*.log*"),
                                    ("all files",
                                     "*.*")))
  if filename:
      # Copy the content of info.log to the selected file
      shutil.copyfile('suspicious_packets.log', filename)

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

# Create a "No suspicious" button
no_error_label = tk.Label(root, text="No suspicious packets found")
no_error_label.config(font=("Courier", 12))
no_error_label.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
no_error_label.place_forget()
# Create a "Download Report" button
error_label = tk.Label(root, text="Suspicious packets found")
error_label.config(font=("Courier", 10))
error_label.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
error_label.place_forget()

button_download = tk.Button(root, text="Download Report", command=downloadReport, bg='red',fg='black')
button_download.config(font=("Courier", 12))
button_download.place(relx=0.5, rely=0.8, anchor=tk.CENTER)
button_download.place_forget()

# Register delete_log_files() with atexit
atexit.register(delete_log_files)
root.mainloop()
