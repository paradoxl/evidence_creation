# This script will automatically generate hash values and create a 1-1 image of the file
# This script will then compare the hash values of the original file and the image file to ensure they match
# This script is designed to be used in a forensic investigation to ensure the integrity of the data
# This script is tested on linux only. It may not work on windows
# Author: Michael Evans
# Company: STGen

import hashlib
import os

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


print("This tool will automatically generate hash values and create a 1-1 image of the file")
print("\n")
print("Please enter the file path of the victim drive \n")
file_path = input()
print('\n')
print("please enter the destination path")
dst_path = input()
validate = input("You have chosen victim path: " + file_path + " and destination path: " + dst_path + "Is this correct?")

if validate.lower() == "y" or validate.lower() == "yes":
    vic_md5 = md5(file_path)
    vic_sha1 = sha1(file_path)
    vic_sha256 = sha256(file_path)
    create_dd_image(file_path, dst_path)
    working_md5 = md5(dst_path)
    working_sha1 = sha1(dst_path)
    working_sha256 = sha256(dst_path)

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
