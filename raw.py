from tkinter import *
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import os
import base64

class SecureStegano:
    def __init__(self, root):
        self.root = root
        self.root.title(" Steganography Tool")
        self.root.geometry("700x550")
        self.root.configure(bg="#E3F2FD")
        
        self.image_path = None
        self.cipher_key = None
        
        self.create_widgets()

    def create_widgets(self):
        # Load and display the Softwarica logo
        try:
            logo_img = Image.open(r"C:\Users\decision\Desktop\sem 5 coursework\crypto\softwarica.logo.jpg") 
            # Ensure the file is in the same directory
            logo_img = logo_img.resize((200, 50))
            self.logo = ImageTk.PhotoImage(logo_img)
            Label(self.root, image=self.logo, bg="blue").pack(pady=5)
        except Exception as e:
            print("Error loading logo:", e)

        Label(self.root, text=" Steganography Tool", font=("Arial", 20, "bold"), fg="white", bg="#2C3E50").pack(pady=10)
        
        frame = Frame(self.root, bg="#E3F2FD")
        frame.pack(pady=10)


        Label(frame, text="Passphrase:", font=("Arial", 12), fg="white", bg="#2C3E50").grid(row=0, column=0, padx=10, pady=5, sticky=W)
        self.passphrase_entry = Entry(frame, show="*", width=30, font=("Arial", 12))
        self.passphrase_entry.grid(row=0, column=1, pady=5)
        
        Label(frame, text="Cipher Algorithm:", font=("Arial", 12), fg="white", bg="#2C3E50").grid(row=1, column=0, padx=10, pady=5, sticky=W)
        self.cipher_combo = ttk.Combobox(frame, values=["AES-256"], state="readonly", width=27, font=("Arial", 12))
        self.cipher_combo.current(0)
        self.cipher_combo.grid(row=1, column=1, pady=5)
        
        Label(self.root, text="Message:", font=("Arial", 12), fg="white", bg="#2C3E50").pack(anchor=W, padx=20)
        self.message_text = Text(self.root, width=80, height=8, font=("Arial", 12))
        self.message_text.pack(pady=5, padx=20)
        
        button_frame = Frame(self.root, bg="#E3F2FD")
        button_frame.pack(pady=10)

        Button(button_frame, text="Open Image", command=self.open_image, bg="green", fg="white", font=("Arial", 12)).grid(row=0, column=0, padx=5)
        Button(button_frame, text="Hide Data", command=self.hide_data, bg="blue", fg="white", font=("Arial", 12)).grid(row=0, column=1, padx=5)
        Button(button_frame, text="Reveal Data", command=self.reveal_data, bg="orange", fg="white", font=("Arial", 12)).grid(row=0, column=2, padx=5)
        Button(button_frame, text="Clear", command=self.clear_fields, bg="red", fg="white", font=("Arial", 12)).grid(row=0, column=3, padx=5)
        Button(button_frame, text="Exit", command=self.root.quit, bg="purple", fg="white", font=("Arial", 12)).grid(row=0, column=4, padx=5)

    def encrypt_text(self):
        text = self.text_entry.get()
        passphrase = self.passphrase_entry.get()
        if not text or not passphrase:
            messagebox.showerror("Error", "Enter text and passphrase!")
            return

        key = self.generate_key(passphrase)
        cipher = Fernet(key)
        encrypted_text = cipher.encrypt(text.encode()).decode()
        self.message_text.delete("1.0", END)
        self.message_text.insert("1.0", encrypted_text)
        messagebox.showinfo("Success", "Text Encrypted!")
        
    def open_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.image_path = file_path
            messagebox.showinfo("Success", "Image Loaded Successfully")
    
    def generate_key(self, passphrase):
        key = base64.urlsafe_b64encode(passphrase.ljust(32).encode("utf-8")[:32])
        return key
    
    def hide_data(self):
        if not self.image_path or not self.passphrase_entry.get():
            messagebox.showerror("Error", "Select an image and enter a passphrase!")
            return
        
        message = self.message_text.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "Enter a message to hide!")
            return
        
        key = self.generate_key(self.passphrase_entry.get())
        cipher = Fernet(key)
        encrypted_message = cipher.encrypt(message.encode())
        
        img = Image.open(self.image_path)
        binary_data = ''.join(format(byte, "08b") for byte in encrypted_message)
        pixels = list(img.getdata())
        
        for i in range(len(binary_data)):
            pixel = list(pixels[i])
            pixel[i % 3] = pixel[i % 3] & ~1 | int(binary_data[i])
            pixels[i] = tuple(pixel)
        
        img.putdata(pixels)
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if save_path:
            img.save(save_path)
            messagebox.showinfo("Success", "Data Hidden Successfully!")
    
    def reveal_data(self):
        if not self.image_path or not self.passphrase_entry.get():
            messagebox.showerror("Error", "Select an image and enter a passphrase!")
            return
        
        key = self.generate_key(self.passphrase_entry.get())
        cipher = Fernet(key)
        
        img = Image.open(self.image_path)
        pixels = list(img.getdata())
        binary_data = "".join(str(pixel[i % 3] & 1) for i, pixel in enumerate(pixels[:5000]))
        byte_data = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        
        try:
            decrypted_message = cipher.decrypt(bytes(int(b, 2) for b in byte_data if len(b) == 8)).decode()
            self.message_text.delete("1.0", END)
            self.message_text.insert("1.0", decrypted_message)
            messagebox.showinfo("Success", "Message Revealed Successfully!")
        except:
            messagebox.showerror("Error", "Incorrect Passphrase or Corrupted Image!")
    
    def clear_fields(self):
        self.message_text.delete("1.0", END)
        self.passphrase_entry.delete(0, END)
        self.image_path = None
        messagebox.showinfo("Cleared", "All Fields Cleared!")

if __name__ == "__main__":
    root = Tk()
    app = SecureStegano(root)
    root.mainloop()
