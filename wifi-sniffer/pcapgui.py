import tkinter as tk
import pcapScrape

def run_pcapScrape():
   current_option = drop_down_menu.cget("text")
   # Pass the current option to the main function
   pcapScrape.main(current_option)

root = tk.Tk()
root.geometry("200x300")

label = tk.Label(root, text="Select a pcap file to scan")
label.pack()
options = ['example-tptk-attack.pcapng', 'example-ft.pcapng', 'ipv4frags.pcap', 'nf9-juniper-vmx.pcapng.cap', 'smtp.pcap', 'teardrop.cap', 'nf9-error.pcapng.cap', 'example-tptk-success.pcap']

# Create a variable to hold the current option
current_option = tk.StringVar()
current_option.set(options[0]) # Set the default option

# Create the drop-down menu
drop_down_menu = tk.OptionMenu(root, current_option, *options)
drop_down_menu.pack()

button = tk.Button(root, text="Click me!", command=run_pcapScrape)
button.pack()

root.mainloop()