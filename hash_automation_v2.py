import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

def md5(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.md5()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()

def sha1(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha1()
        while chunk := f.read(65536):
            file_hash.update(chunk)
    return file_hash.hexdigest()

def sha256(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256()
        while chunk := f.read(4096):
            file_hash.update(chunk)
    return file_hash.hexdigest()

def create_dd_image(input_device, output_file, block_size=4096, progress_interval=1000000):
    total_size = os.path.getsize(input_device)
    bytes_copied = 0

    with open(input_device, 'rb') as source, open(output_file, 'wb') as destination:
        while True:
            chunk = source.read(block_size)
            if not chunk:
                break
            destination.write(chunk)
            bytes_copied += len(chunk)
            
            if bytes_copied % progress_interval == 0:
                progress = (bytes_copied / total_size) * 100
                print(f"Progress: {progress:.2f}%")

    print("Image creation completed.")

def select_file_path():
    file_path.set(filedialog.askopenfilename())
    print(f"File path set to: {file_path.get()}")

def select_dst_path():
    dst_path.set(filedialog.askdirectory())
    print(f"Destination path set to: {dst_path.get()}")

def start_process():
    if file_path.get() and dst_path.get():
        validate = messagebox.askyesno("Confirm Paths", f"You have chosen victim path: {file_path.get()} and destination path: {dst_path.get()}. Is this correct?")
        if validate:
            vic_md5 = md5(file_path.get())
            vic_sha1 = sha1(file_path.get())
            vic_sha256 = sha256(file_path.get())
            
            # Generate a unique output file name
            base_name = os.path.basename(file_path.get())
            name, ext = os.path.splitext(base_name)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_file = os.path.join(dst_path.get(), f"{name}_{timestamp}{ext}")
            
            create_dd_image(file_path.get(), output_file)
            working_md5 = md5(output_file)
            working_sha1 = sha1(output_file)
            working_sha256 = sha256(output_file)

            # Update the GUI with the hash values
            victim_md5_var.set(vic_md5)
            victim_sha1_var.set(vic_sha1)
            victim_sha256_var.set(vic_sha256)
            destination_md5_var.set(working_md5)
            destination_sha1_var.set(working_sha1)
            destination_sha256_var.set(working_sha256)

            if vic_md5 == working_md5:
                print("MD5 Match")
            else:
                print("MD5 Hash does not match")

            if vic_sha1 == working_sha1:
                print("SHA1 Match")
            else:
                print("SHA1 Hash does not match")

            if vic_sha256 == working_sha256:
                print("SHA256 Match")
                print("\nAll systems are operational")
            else:
                print("SHA256 Hash does not match")
        else:
            print("beep boop")
    else:
        messagebox.showerror("Error", "Please provide both file paths.")

# Create the main window
root = tk.Tk()
root.title("File Hash and Image Tool")

file_path = tk.StringVar()
dst_path = tk.StringVar()
victim_md5_var = tk.StringVar()
victim_sha1_var = tk.StringVar()
victim_sha256_var = tk.StringVar()
destination_md5_var = tk.StringVar()
destination_sha1_var = tk.StringVar()
destination_sha256_var = tk.StringVar()

# Create and place the widgets
tk.Label(root, text="Select the victim file:").pack(pady=10)
tk.Entry(root, textvariable=file_path, width=50).pack(pady=10)
tk.Button(root, text="Browse", command=select_file_path).pack(pady=5)

tk.Label(root, text="Select the destination directory:").pack(pady=10)
tk.Entry(root, textvariable=dst_path, width=50).pack(pady=10)
tk.Button(root, text="Browse", command=select_dst_path).pack(pady=5)

tk.Button(root, text="Start Process", command=start_process).pack(pady=20)

# Display hash values
tk.Label(root, text="Victim MD5:").pack(pady=5)
tk.Entry(root, textvariable=victim_md5_var, width=50, state='readonly').pack(pady=5)
tk.Label(root, text="Victim SHA1:").pack(pady=5)
tk.Entry(root, textvariable=victim_sha1_var, width=50, state='readonly').pack(pady=5)
tk.Label(root, text="Victim SHA256:").pack(pady=5)
tk.Entry(root, textvariable=victim_sha256_var, width=50, state='readonly').pack(pady=5)

tk.Label(root, text="Destination MD5:").pack(pady=5)
tk.Entry(root, textvariable=destination_md5_var, width=50, state='readonly').pack(pady=5)
tk.Label(root, text="Destination SHA1:").pack(pady=5)
tk.Entry(root, textvariable=destination_sha1_var, width=50, state='readonly').pack(pady=5)
tk.Label(root, text="Destination SHA256:").pack(pady=5)
tk.Entry(root, textvariable=destination_sha256_var, width=50, state='readonly').pack(pady=5)

# Run the main loop
root.mainloop()