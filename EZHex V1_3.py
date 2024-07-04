import tkinter
import customtkinter
from PIL import Image
from ctkdlib.custom_widgets import *
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import struct
import subprocess

# Define the function to validate Fortnite folder
def validate_fortnite_folder(folder_path):
    fortnite_executable = os.path.join(folder_path, "FortniteGame", "Binaries", "Win64", "FortniteClient-Win64-Shipping.exe")
    if os.path.exists(fortnite_executable):
        return True
    else:
        return False

# Define the function for selecting Fortnite folder
def select_fortnite_folder():
    folder_path = filedialog.askdirectory(title="Select Fortnite Folder")
    if folder_path:
        if validate_fortnite_folder(folder_path):
            messagebox.showinfo("Fortnite Folder", "Fortnite folder validated successfully!")
            switch_page(Page_4)  # Navigate to Page 4
        else:
            messagebox.showerror("Fortnite Folder", "Invalid Fortnite folder! Please select the correct folder.")

customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")


def switch_page(page):
    pages = [Page_1, Page_2, Page_3, Page_4, Page_5]
    for i in pages:
        i.pack_forget()
    page.pack(expand=True, fill='both')

    fixed_widgets = []
    for widget in fixed_widgets:
        widget.lift()
        widget.place(x=widget.winfo_x(), y=widget.winfo_y())


HEIGHT = 800
WIDTH = 1200

root = customtkinter.CTk()
root.title("EZHex V1_3")
root.geometry((f"{WIDTH}x{HEIGHT}"))
root.resizable(False, False)

Page_1 = customtkinter.CTkFrame(root, fg_color='transparent', corner_radius=0, border_width=0)
Page_1.pack(expand=True, fill='both')
Page_2 = customtkinter.CTkFrame(root, fg_color='transparent', corner_radius=0, border_width=0)
Page_3 = customtkinter.CTkFrame(root, fg_color='transparent', corner_radius=0, border_width=0)
Page_4 = customtkinter.CTkFrame(root, fg_color='transparent', corner_radius=0, border_width=0)
Page_5 = customtkinter.CTkFrame(root, fg_color='transparent', corner_radius=0, border_width=0)

Label1 = customtkinter.CTkLabel(master=Page_1, text="")
Label1.place(x=438, y=124)

Label2 = customtkinter.CTkLabel(master=Page_1, font=customtkinter.CTkFont('', size=85, weight='bold'), text="EZ")
Label2.place(x=501, y=220)

Label3 = customtkinter.CTkLabel(master=Page_1, font=customtkinter.CTkFont('', size=34, weight='bold'), text="HEX")
Label3.place(x=611, y=266)

Label4 = customtkinter.CTkLabel(master=Page_2, text="")
Label4.place(x=438, y=124)

Label5 = customtkinter.CTkLabel(master=Page_2, font=customtkinter.CTkFont('', size=85, weight='bold'), text="EZ")
Label5.place(x=518, y=181)

Label6 = customtkinter.CTkLabel(master=Page_2, font=customtkinter.CTkFont('', size=34, weight='bold'), text="HEX")
Label6.place(x=627, y=227)

SearchTextInputBox = customtkinter.CTkEntry(master=Page_2, placeholder_text="HEX Search Value")
SearchTextInputBox.place(x=541, y=300)

Label7 = customtkinter.CTkLabel(master=Page_2, text="Search:")
Label7.place(x=588, y=269)

Label8 = customtkinter.CTkLabel(master=Page_2, text="Replace:")
Label8.place(x=586, y=332)

ReplaceTextInputBox = customtkinter.CTkEntry(master=Page_2, placeholder_text="HEX Replace Value")
ReplaceTextInputBox.place(x=540, y=361)

SwapButton = customtkinter.CTkButton(
    master=Page_2,
    corner_radius=14,
    text="SWAP",
    fg_color="#753c88",
    hover_color="#443054")
SwapButton.place(x=540, y=399)

Label9 = customtkinter.CTkLabel(master=Page_3, text="")
Label9.place(x=438, y=124)

Label10 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=34, weight='bold'), text="")
Label10.place(x=653, y=86)

HEXTextBox = customtkinter.CTkTextbox(master=Page_3, width=369, height=438)
HEXTextBox.place(x=805, y=37)

Label11 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=26, weight='bold'), text="HEX")
Label11.place(x=977, y=4)

Frame1 = customtkinter.CTkFrame(master=Page_3, width=875, height=61, fg_color="#191919", border_color="#373737")
Frame1.place(x=157, y=733)

def load_uasset_file():
    file_path = filedialog.askopenfilename(
        title="Select Uasset File",
        filetypes=[("Uasset Files", "*.uasset"), ("Pak Files", "*.pak"), ("Ucas Files", "*.ucas"),
                   ("Utoc Files", "*.utoc"), ("Sig Files", "*.sig")])
    
    if file_path:
        try:
            # Read and process the file
            with open(file_path, "rb") as f:
                # Read hex bytes and format for display
                hex_data = f.read().hex().upper()  # Read bytes and convert to hex string
                hex_lines = [hex_data[i:i + 2] for i in range(0, len(hex_data), 2)]  # Split into pairs of characters

                HEXTextBox.delete("1.0", tk.END)
                HEXTextBox.insert(tk.END, " ".join(hex_lines))  # Join pairs with space

                # Reset other text boxes
                RawValuesTextBox.delete("1.0", tk.END)
                StringsTextBox.delete("1.0", tk.END)
                FloatingPointTextBox.delete("1.0", tk.END)
                IntegersTextBox.delete("1.0", tk.END)
                OffsetsTextBox.delete("1.0", tk.END)

                # Read raw text
                f.seek(0)
                raw_text = f.read().decode(errors='ignore')
                RawValuesTextBox.insert(tk.END, raw_text)

                # Extract strings and format them for readability
                strings = []
                current_string = []
                for i in range(0, len(hex_data), 2):
                    byte = int(hex_data[i:i + 2], 16)
                    if 32 <= byte <= 126:  # ASCII printable characters range
                        current_string.append(chr(byte))
                    else:
                        if current_string:
                            strings.append("".join(current_string))
                            current_string = []
                if current_string:
                    strings.append("".join(current_string))
                
                # Format strings to display without spaces
                formatted_strings = "".join(strings)
                StringsTextBox.insert(tk.END, formatted_strings)

                # Extract floating point values
                floating_points = []
                for i in range(0, len(hex_data), 16):  # Assuming each floating point value is 8 bytes (64 bits)
                    hex_value = hex_data[i:i + 16]  # 8 bytes = 16 hex characters
                    if len(hex_value) == 16:
                        float_value = struct.unpack('d', bytes.fromhex(hex_value))[0]  # Convert hex to double
                        floating_points.append(f"{float_value:.6f}")  # Format as float with 6 decimal places
                FloatingPointTextBox.insert(tk.END, "\n".join(floating_points))

                # Extract integers
                integers = []
                for i in range(0, len(hex_data), 8):  # Assuming each integer value is 4 bytes (32 bits)
                    hex_value = hex_data[i:i + 8]  # 4 bytes = 8 hex characters
                    if len(hex_value) == 8:
                        int_value = struct.unpack('I', bytes.fromhex(hex_value))[0]  # Convert hex to unsigned int
                        integers.append(str(int_value))
                IntegersTextBox.insert(tk.END, "\n".join(integers))

                # Extract offsets
                offsets = []
            for i in range(0, len(hex_data), 8):  # Assuming each offset value is 4 bytes (32 bits)
                hex_value = hex_data[i:i + 8]  # 4 bytes = 8 hex characters
                if len(hex_value) == 8:
                  int_value = struct.unpack('I', bytes.fromhex(hex_value))[0]  # Convert hex to unsigned int
                  offset_value = f"0x{int_value:08X}"  # Format as hexadecimal with leading '0x' and 8 characters
                  offsets.append(offset_value)
            OffsetsTextBox.insert(tk.END, "\n".join(offsets))

        except Exception as e:
            messagebox.showerror("Error", f"Error loading file: {str(e)}")

LoadUassetButton = customtkinter.CTkButton(
    master=Page_3,
    bg_color="#191919",
    corner_radius=14,
    text="Load Uasset",
    fg_color="#5c1c64",
    hover_color="#4f3351",
    command=load_uasset_file)
LoadUassetButton.place(x=167, y=749)

def export_to_txt():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        title="Save As TXT")
    if file_path:
        with open(file_path, "w") as f:
            f.write(f"HEX Data:\n{HEXTextBox.get('1.0', tk.END)}\n\n")
            f.write(f"Raw Values:\n{RawValuesTextBox.get('1.0', tk.END)}\n\n")
            f.write(f"Strings:\n{StringsTextBox.get('1.0', tk.END)}\n\n")
            f.write(f"Floating Point Values:\n{FloatingPointTextBox.get('1.0', tk.END)}\n\n")
            f.write(f"Integers:\n{IntegersTextBox.get('1.0', tk.END)}\n\n")
            f.write(f"Offsets:\n{OffsetsTextBox.get('1.0', tk.END)}\n\n")
        messagebox.showinfo("Export Complete", f"Data exported to {file_path}")

ExportAsTXTButton = customtkinter.CTkButton(
    master=Page_3,
    bg_color="#191919",
    corner_radius=14,
    text="Export as TXT",
    fg_color="#5c1c64",
    hover_color="#4f3351",
    command=export_to_txt)
ExportAsTXTButton.place(x=312, y=750)

Button4 = customtkinter.CTkButton(
    master=Page_3,
    bg_color="#191919",
    corner_radius=14,
    text="BACK",
    fg_color="#5c1c64",
    hover_color="#4f3351",
    command=lambda: switch_page(Page_4),
    width=65)
Button4.place(x=958, y=749)

Button5 = customtkinter.CTkButton(
    master=Page_2,
    corner_radius=14,
    text="BACK",
    fg_color="#753c88",
    hover_color="#443054",
    command=lambda: switch_page(Page_4),
    width=60)
Button5.place(x=580, y=433)

FloatingPointTextBox = customtkinter.CTkTextbox(master=Page_3, width=270, height=210)
FloatingPointTextBox.place(x=527, y=517)

Label12 = customtkinter.CTkLabel(
    master=Page_3,
    font=customtkinter.CTkFont(
        '',
        size=26,
        weight='bold'),
    text="FLOATING POINT")
Label12.place(x=556, y=484)

StringsTextBox = customtkinter.CTkTextbox(master=Page_3, width=369, height=210)
StringsTextBox.place(x=153, y=516)

Label13 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=26, weight='bold'), text="STRINGS")
Label13.place(x=285, y=483)

OffsetsTextBox = customtkinter.CTkTextbox(master=Page_3, width=112, height=210)
OffsetsTextBox.place(x=1063, y=517)

Label14 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=19, weight='bold'), text="OFFSETS")
Label14.place(x=1074, y=488)

IntegersTextBox = customtkinter.CTkTextbox(master=Page_3, width=252, height=210)
IntegersTextBox.place(x=804, y=517)

Label15 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=26, weight='bold'), text="INTEGERS")
Label15.place(x=869, y=483)

RawValuesTextBox = customtkinter.CTkTextbox(master=Page_3, width=369, height=438)
RawValuesTextBox.place(x=431, y=37)

Label16 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=26, weight='bold'), text="RAW")
Label16.place(x=593, y=4)

Label17 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=78, weight='bold'), text="EZ")
Label17.place(x=151, y=23)

Label18 = customtkinter.CTkLabel(master=Page_3, font=customtkinter.CTkFont('', size=38, weight='bold'), text="HEX")
Label18.place(x=252, y=60)

Label19 = customtkinter.CTkLabel(
    master=Page_3, font=customtkinter.CTkFont(
        '', size=17, weight='bold'), text="PAK CREATOR")
Label19.place(x=154, y=100)

Label20 = customtkinter.CTkLabel(
    master=Page_3,
    font=customtkinter.CTkFont(
        '',
        size=9,
        weight='bold',
        underline=1),
    text="BETA")
Label20.place(x=276, y=100)

Label21 = customtkinter.CTkLabel(master=Page_4, text="")
Label21.place(x=438, y=124)

Label22 = customtkinter.CTkLabel(master=Page_4, font=customtkinter.CTkFont('', size=85, weight='bold'), text="EZ")
Label22.place(x=501, y=220)

Label23 = customtkinter.CTkLabel(master=Page_4, font=customtkinter.CTkFont('', size=34, weight='bold'), text="HEX")
Label23.place(x=611, y=266)

Button6 = customtkinter.CTkButton(
    master=Page_4,
    corner_radius=14,
    text="Swapper",
    fg_color="#753c88",
    hover_color="#443054",
    command=lambda: switch_page(Page_2))
Button6.place(x=524, y=311)

Button7 = customtkinter.CTkButton(
    master=Page_4,
    corner_radius=14,
    text="Pak Creator | BETA",
    fg_color="#753c88",
    hover_color="#443054",
    command=lambda: switch_page(Page_3))
Button7.place(x=524, y=376)

Hyperlink1 = CTkHyperlink(
    master=Page_4,
    url="https://discord.gg/KbuBHAbMvc",
    font=customtkinter.CTkFont(
        '',
        size=34,
        weight='bold'),
    text="JOIN THE DISCORD",
    bg_color=[
        'gray92',
        'gray14'])
Hyperlink1.place(x=427, y=411)

Button8 = customtkinter.CTkButton(
    master=Page_4,
    corner_radius=14,
    text="EZHex Launcher",
    fg_color="#753c88",
    hover_color="#443054",
    command=lambda: switch_page(Page_5))
Button8.place(x=524, y=343)

Frame2 = customtkinter.CTkFrame(master=Page_4, width=423, height=142, corner_radius=19)
Frame2.place(x=10, y=647)

Label24 = customtkinter.CTkLabel(
    master=Page_4,
    bg_color=[
        'gray86',
        'gray17'],
    font=customtkinter.CTkFont(
        '',
        size=32,
        weight='bold'),
    text="⚠️")
Label24.place(x=381, y=651)

Label25 = customtkinter.CTkLabel(
    master=Page_4,
    bg_color=[
        'gray86',
        'gray17'],
    font=customtkinter.CTkFont(
        '',
        size=28,
        weight='bold'),
    text="IMPORTANT!")
Label25.place(x=23, y=651)

Label26 = customtkinter.CTkLabel(master=Page_4, bg_color=['gray86', 'gray17'], font=customtkinter.CTkFont(
    '', size=14), text="The EZHex pak creator is currently in Beta! This means it")
Label26.place(x=24, y=682)

Label27 = customtkinter.CTkLabel(master=Page_4, bg_color=['gray86', 'gray17'], font=customtkinter.CTkFont(
    '', size=14), text="will change a lot over time and might break in some updates.")
Label27.place(x=23, y=701)

Label28 = customtkinter.CTkLabel(
    master=Page_4,
    bg_color=[
        'gray86',
        'gray17'],
    font=customtkinter.CTkFont(
        '',
        size=14),
    text="If you find any bugs please report them in the discord!")
Label28.place(x=22, y=721)

Label29 = customtkinter.CTkLabel(
    master=Page_4,
    bg_color=[
        'gray86',
        'gray17'],
    font=customtkinter.CTkFont(
        '',
        size=14,
        weight='bold'),
    text="Thanks everyone ( :")
Label29.place(x=21, y=741)

Button9 = customtkinter.CTkButton(
    master=Page_1,
    corner_radius=12,
    text="Select your Fortnite folder",
    fg_color="#86358e",
    hover_color="#453351",
    command=select_fortnite_folder)
Button9.place(x=511, y=310)

Label30 = customtkinter.CTkLabel(master=Page_5, text="")
Label30.place(x=438, y=124)

Label31 = customtkinter.CTkLabel(master=Page_5, font=customtkinter.CTkFont('', size=85, weight='bold'), text="EZ")
Label31.place(x=501, y=220)

Label32 = customtkinter.CTkLabel(master=Page_5, font=customtkinter.CTkFont('', size=34, weight='bold'), text="HEX")
Label32.place(x=611, y=266)

def find_fortnite_executable(folder_path):
    exe_paths = []
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename == "FortniteClient-Win64-Shipping_EAC_EOS.exe":
                exe_path = os.path.join(root, filename)
                exe_paths.append(exe_path)
    return exe_paths

def launch_fortnite():
    folder_path = filedialog.askdirectory()
    
    if not folder_path:
        messagebox.showerror("Error", "No folder selected")
        return
    
    # Find all paths to the FortniteClient-Win64-Shipping_EAC_EOS.exe in the selected folder and its subfolders
    exe_paths = find_fortnite_executable(folder_path)
    
    if exe_paths:
        for exe_path in exe_paths:
            try:
                subprocess.Popen(exe_path)
                messagebox.showinfo("Launching Fortnite", "Launching Fortnite, please wait...")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to launch Fortnite: {str(e)}")
    else:
        messagebox.showerror("Failed to Launch Fortnite", "Failed to find FortniteClient-Win64-Shipping_EAC_EOS.exe in the selected folder.")

def select_fortnite_folder():
    global selected_fortnite_folder
    selected_fortnite_folder = filedialog.askdirectory()
    print(f"Selected Fortnite folder: {selected_fortnite_folder}")

LaunchFNButton = customtkinter.CTkButton(
    master=Page_5,
    corner_radius=14,
    text="Launch Fortnite",
    fg_color="#753c88",
    hover_color="#443054",
    command=lambda: launch_fortnite()  # Ensure lambda calls the correct function
)
LaunchFNButton.place(x=523, y=311)

Label33 = customtkinter.CTkLabel(
    master=Page_5,
    font=customtkinter.CTkFont(
        '',
        size=13,
        weight='bold'),
    text="NOTE: Launching with this may take a while at the moment. We will fix this in a later update!")
Label33.place(x=312, y=339)

root.mainloop()
