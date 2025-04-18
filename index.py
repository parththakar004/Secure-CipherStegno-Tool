import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image
import numpy as np
import random

# Caesar Cipher Helper Functions
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        elif char.isdigit():
            # Encrypt numbers by shifting within 0-9
            result += str((int(char) + shift) % 10)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base - shift) % 26 + shift_base)
        elif char.isdigit():
            # Decrypt numbers by shifting within 0-9
            result += str((int(char) - shift) % 10)
        else:
            result += char
    return result

# Cryptography Handler
def handle_cryptography():
    def handle_encryption():
        def process_encryption():
            shift_value = shift_entry.get()
            try:
                shift_value = int(shift_value)
            except ValueError:
                messagebox.showwarning("Input Error", "Please enter a valid integer for shift value")
                return
            
            text = input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Input Error", "Please provide text to encrypt")
                return
            
            encrypted_text = caesar_encrypt(text, shift_value)
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.END, encrypted_text)

        encryption_window = tk.Toplevel(root)
        encryption_window.title("Encryption")
        encryption_window.geometry("600x500")
        encryption_window.configure(bg="#f0f0f0")

        tk.Label(encryption_window, text="Enter Shift Value (Integer)", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        shift_entry = tk.Entry(encryption_window, font=("Arial", 12), width=20)
        shift_entry.pack(pady=10)

        tk.Label(encryption_window, text="Enter Text to Encrypt", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        input_text = tk.Text(encryption_window, height=10, width=50, font=("Arial", 12))
        input_text.pack(pady=10)

        tk.Label(encryption_window, text="Output (Encrypted Text)", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        output_text = tk.Text(encryption_window, height=10, width=50, font=("Arial", 12))
        output_text.pack(pady=10)

        tk.Button(encryption_window, text="Encrypt", command=process_encryption, font=("Arial", 14), height=2, width=20, bg="#4CAF50", fg="white").pack(pady=10)

    def handle_decryption():
        def process_decryption():
            shift_value = shift_entry.get()
            try:
                shift_value = int(shift_value)
            except ValueError:
                messagebox.showwarning("Input Error", "Please enter a valid integer for shift value")
                return
            
            text = input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Input Error", "Please provide text to decrypt")
                return
            
            decrypted_text = caesar_decrypt(text, shift_value)
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.END, decrypted_text)

        decryption_window = tk.Toplevel(root)
        decryption_window.title("Decryption")
        decryption_window.geometry("600x500")
        decryption_window.configure(bg="#f0f0f0")

        tk.Label(decryption_window, text="Enter Shift Value (Integer)", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        shift_entry = tk.Entry(decryption_window, font=("Arial", 12), width=20)
        shift_entry.pack(pady=10)

        tk.Label(decryption_window, text="Enter Text to Decrypt", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        input_text = tk.Text(decryption_window, height=10, width=50, font=("Arial", 12))
        input_text.pack(pady=10)

        tk.Label(decryption_window, text="Output (Decrypted Text)", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        output_text = tk.Text(decryption_window, height=10, width=50, font=("Arial", 12))
        output_text.pack(pady=10)

        tk.Button(decryption_window, text="Decrypt", command=process_decryption, font=("Arial", 14), height=2, width=20, bg="#4CAF50", fg="white").pack(pady=10)

    def handle_random_cryptography():
        def process_random_cryptography():
            text = input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Input Error", "Please provide text to process")
                return
            
            shift_value = random.randint(1, 25)
            if random.choice([True, False]):
                result_text = caesar_encrypt(text, shift_value)
                operation = "encrypted"
            else:
                result_text = caesar_decrypt(text, shift_value)
                operation = "decrypted"
            
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.END, result_text)
            messagebox.showinfo("Random Cryptography", f"Text {operation} with shift value {shift_value}")

        random_cryptography_window = tk.Toplevel(root)
        random_cryptography_window.title("Random Cryptography")
        random_cryptography_window.geometry("600x500")
        random_cryptography_window.configure(bg="#f0f0f0")

        tk.Label(random_cryptography_window, text="Enter Text to Process", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        input_text = tk.Text(random_cryptography_window, height=10, width=50, font=("Arial", 12))
        input_text.pack(pady=10)

        tk.Label(random_cryptography_window, text="Output (Processed Text)", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        output_text = tk.Text(random_cryptography_window, height=10, width=50, font=("Arial", 12))
        output_text.pack(pady=10)

        tk.Button(random_cryptography_window, text="Process", command=process_random_cryptography, font=("Arial", 14), height=2, width=20, bg="#4CAF50", fg="white").pack(pady=10)

    cryptography_window = tk.Toplevel(root)
    cryptography_window.title("Cryptography")
    cryptography_window.geometry("400x300")
    cryptography_window.configure(bg="#f0f0f0")

    tk.Button(cryptography_window, text="Encryption", command=handle_encryption, font=("Arial", 14), height=2, width=20, bg="#2196F3", fg="white").pack(pady=10)
    tk.Button(cryptography_window, text="Decryption", command=handle_decryption, font=("Arial", 14), height=2, width=20, bg="#2196F3", fg="white").pack(pady=10)
    tk.Button(cryptography_window, text="Random Cryptography", command=handle_random_cryptography, font=("Arial", 14), height=2, width=20, bg="#2196F3", fg="white").pack(pady=10)

# Image Steganography Functions
def encode_text_in_image(image_path, text, output_path):
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)
    
    binary_text = ''.join(format(ord(c), '08b') for c in text) + '1111111111111110'
    if len(binary_text) > pixels.size * 3:
        raise ValueError("Text is too large to encode in this image.")
    
    idx = 0
    for row in range(pixels.shape[0]):
        for col in range(pixels.shape[1]):
            if idx < len(binary_text):
                pixel = list(pixels[row, col])
                for i in range(3):
                    if idx < len(binary_text):
                        pixel[i] = (pixel[i] & ~1) | int(binary_text[idx])
                        idx += 1
                pixels[row, col] = tuple(pixel)
            else:
                break
        if idx >= len(binary_text):
            break
    
    modified_image = Image.fromarray(pixels.astype(np.uint8))
    modified_image.save(output_path)

def extract_text_from_image(image_path):
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)
    
    binary_text = ""
    for row in range(pixels.shape[0]):
        for col in range(pixels.shape[1]):
            pixel = pixels[row, col]
            for i in range(3):
                binary_text += str(pixel[i] & 1)
    
    delimiter = "1111111111111110"
    if delimiter in binary_text:
        binary_text = binary_text.split(delimiter)[0]
        return "".join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
    return ""

def handle_image_steganography():
    def encode_image():
        image_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image Files", "*.png;*.bmp")])
        if not image_path:
            return
        
        message = text_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Input Error", "Please provide a message to encode")
            return
        
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("Image Files", "*.png;*.bmp")])
        if not output_path:
            return
        
        try:
            encode_text_in_image(image_path, message, output_path)
            messagebox.showinfo("Success", f"Message successfully encoded in {output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_image():
        image_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image Files", "*.png;*.bmp")])
        if not image_path:
            return
        
        try:
            decoded_message = extract_text_from_image(image_path)
            if decoded_message:
                messagebox.showinfo("Decoded Message", decoded_message)
            else:
                messagebox.showinfo("Decoded Message", "No hidden message found")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    image_steganography_window = tk.Toplevel(root)
    image_steganography_window.title("Image Steganography")
    image_steganography_window.geometry("600x400")
    image_steganography_window.configure(bg="#f0f0f0")

    tk.Label(image_steganography_window, text="Enter Message to Encode", font=("Arial", 12), bg="#f0f0f0").pack(pady=10)
    text_entry = tk.Text(image_steganography_window, height=10, width=50, font=("Arial", 12))
    text_entry.pack(pady=10)

    tk.Button(image_steganography_window, text="Encode Message", command=encode_image, font=("Arial", 14), height=2, width=20, bg="#4CAF50", fg="white").pack(pady=10)
    tk.Button(image_steganography_window, text="Decode Message", command=decode_image, font=("Arial", 14), height=2, width=20, bg="#4CAF50", fg="white").pack(pady=10)

# Main GUI Window
root = tk.Tk()
root.title("Cryptography and Steganography Tool")
root.geometry("600x400")
root.configure(bg="#f0f0f0")

tk.Label(root, text="Welcome to Cryptography & Steganography", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
tk.Button(root, text="Cryptography", command=handle_cryptography, font=("Arial", 14), height=3, width=20, bg="#2196F3", fg="white").pack(pady=10)
tk.Button(root, text="Steganography", command=handle_image_steganography, font=("Arial", 14), height=3, width=20, bg="#2196F3", fg="white").pack(pady=10)

copyright_label = tk.Label(root, text=" PARTH THAKAR © 2025 Tool", font=("Arial", 10), bg="#f0f0f0")
copyright_label.pack(side=tk.BOTTOM, pady=10)

root.mainloop()