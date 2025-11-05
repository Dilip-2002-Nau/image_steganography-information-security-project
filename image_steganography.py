import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import os

# ---------- Utility Functions ----------
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

def binary_to_message(binary_data):
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return ''.join(chr(int(b, 2)) for b in chars)

# ---------- Encode Function ----------
def encode_image(input_image_path, message, output_image_path):
    image = Image.open(input_image_path)
    if image.mode != 'RGB':
        image = image.convert('RGB')

    data = list(image.getdata())

    # Add binary message with end marker
    binary_message = message_to_binary(message) + message_to_binary(chr(255) + chr(254))
    data_index = 0
    new_data = []

    for pixel in data:
        pixel = list(pixel)
        for i in range(3):  # Modify R, G, B bits
            if data_index < len(binary_message):
                pixel[i] = pixel[i] & ~1 | int(binary_message[data_index])
                data_index += 1
        new_data.append(tuple(pixel))

    image.putdata(new_data)
    image.save(output_image_path)
    messagebox.showinfo("✅ Success", f"Message encoded successfully!\nSaved as:\n{output_image_path}")

# ---------- Decode Function ----------
def decode_image(input_image_path):
    image = Image.open(input_image_path)
    if image.mode != 'RGB':
        image = image.convert('RGB')

    data = list(image.getdata())
    binary_data = ''

    for pixel in data:
        for value in pixel[:3]:
            binary_data += str(value & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_message = ''
    for byte in all_bytes:
        decoded_message += chr(int(byte, 2))
        # Stop reading when end marker is found
        if decoded_message.endswith(chr(255) + chr(254)):
            decoded_message = decoded_message[:-2]
            break

    messagebox.showinfo("🔓 Decoded Message", decoded_message)
    return decoded_message

# ---------- GUI Handlers ----------
def browse_image():
    filename = filedialog.askopenfilename(
        title="Select an Image",
        filetypes=[("Image Files", "*.png *.bmp *.jpg *.jpeg")]
    )
    entry_image_path.delete(0, tk.END)
    entry_image_path.insert(0, filename)

def encode_action():
    input_image = entry_image_path.get()
    secret_message = text_message.get("1.0", tk.END).strip()
    if not input_image or not secret_message:
        messagebox.showerror("⚠️ Error", "Please select an image and enter a message.")
        return
    output_image = os.path.splitext(input_image)[0] + "_stego.png"
    encode_image(input_image, secret_message, output_image)

    # 🔹 Clear the text box after encoding
    text_message.delete("1.0", tk.END)

def decode_action():
    input_image = entry_image_path.get()
    if not input_image:
        messagebox.showerror("⚠️ Error", "Please select an image to decode.")
        return
    decode_image(input_image)

# ---------- GUI Layout ----------
root = tk.Tk()
root.title("🖼️ Image Steganography - Hide Secret Message")
root.geometry("600x400")
root.config(bg="#1e1e1e")

tk.Label(root, text="Image Steganography", fg="white", bg="#1e1e1e",
         font=("Arial", 20, "bold")).pack(pady=10)

frame1 = tk.Frame(root, bg="#1e1e1e")
frame1.pack(pady=10)
tk.Label(frame1, text="Image Path:", fg="white", bg="#1e1e1e",
         font=("Arial", 12)).grid(row=0, column=0, padx=10)
entry_image_path = tk.Entry(frame1, width=40)
entry_image_path.grid(row=0, column=1)
tk.Button(frame1, text="Browse", command=browse_image,
          bg="#0078D7", fg="white", width=10).grid(row=0, column=2, padx=10)

tk.Label(root, text="Secret Message:", fg="white", bg="#1e1e1e",
         font=("Arial", 12)).pack()
text_message = tk.Text(root, width=60, height=5)
text_message.pack(pady=5)

frame2 = tk.Frame(root, bg="#1e1e1e")
frame2.pack(pady=10)
tk.Button(frame2, text="🔒 Encode", command=encode_action,
          bg="#28a745", fg="white", width=15, font=("Arial", 11, "bold")).grid(row=0, column=0, padx=20)
tk.Button(frame2, text="🔓 Decode", command=decode_action,
          bg="#dc3545", fg="white", width=15, font=("Arial", 11, "bold")).grid(row=0, column=1, padx=20)

tk.Label(root, text="Developed by Dilip | Information Security Project",
         fg="#aaaaaa", bg="#1e1e1e", font=("Arial", 9)).pack(side=tk.BOTTOM, pady=10)

root.mainloop()
