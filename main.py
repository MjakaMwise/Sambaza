import socketserver
import threading
import pyautogui
import io
import socket
import customtkinter as ctk
from tkinter import messagebox
import secrets
import hashlib
from urllib.parse import parse_qs

# Class for handling screen capture requests and streaming
class ScreenCapture(socketserver.BaseRequestHandler):
    # Handle incoming requests
    def handle(self):
        try:
            # Receive and decode incoming request data
            request_data = self.request.recv(1024).decode('utf-8')
            
            # Check if the request contains a password query
            if '?' in request_data.split('\n')[0]:
                query_string = request_data.split('\n')[0].split('?')[1].split(' ')[0]
                params = parse_qs(query_string)
                provided_password = params.get('pass', [''])[0]
                
                # Verify password; if incorrect, show the authentication page
                if not self.verify_password(provided_password):
                    self.send_auth_page()
                    return
            else:
                self.send_auth_page()
                return
            
            # Log the connection and begin streaming the screen
            self.log_connection()
            self.stream_screen()
            
        except Exception as e:
            print(f"Error handling request: {e}")
    
    # Verifies the provided password with the server's stored password
    def verify_password(self, provided_password):
        if not provided_password:
            return False
        
        # Hash the provided password and compare with the server's password hash
        server_password = getattr(self.server, 'stream_password', '')
        provided_hash = hashlib.sha256(provided_password.encode()).hexdigest()
        server_hash = hashlib.sha256(server_password.encode()).hexdigest()
        
        return provided_hash == server_hash
    
    # Sends the HTML authentication page
    def send_auth_page(self):
        html = """ ... """  # HTML content for the password input page
        response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(html)}\r\n\r\n{html}"
        self.request.sendall(response.encode())
    
    # Logs the client connection details
    def log_connection(self):
        client_ip = self.client_address[0]
        print(f"✓ Client connected: {client_ip}")
        if hasattr(self.server, 'update_connections'):
            self.server.active_connections = getattr(self.server, 'active_connections', 0) + 1
            self.server.update_connections()
    
    # Streams the screen as JPEG images to the client
    def stream_screen(self):
        self.request.sendall(b"HTTP/1.1 200 OK\r\n")
        self.request.sendall(b"Content-type: multipart/x-mixed-replace; boundary=frame\r\n")
        self.request.sendall(b"\r\n")

        # Continuously send screen captures to the client
        while getattr(self.server, "is_running", False):
            try:
                scrnsht = pyautogui.screenshot()
                BinImg = io.BytesIO()
                scrnsht.save(BinImg, format='JPEG', quality=75)
                BinImg.seek(0)

                self.request.sendall(b"--frame\r\n")
                self.request.sendall(b"Content-type: image/jpeg\r\n")
                self.request.sendall(f"Content-length: {len(BinImg.getvalue())}\r\n".encode())
                self.request.sendall(b"\r\n")
                self.request.sendall(BinImg.getvalue())
                self.request.sendall(b"\r\n")
            except:
                break


# Helper functions for server management and network utilities
def get_private_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Unable to get IP"

# Generates a TV code based on the IP and port for accessing the stream
def generate_tv_code(ip, port):
    ip_parts = ip.split('.')
    code = ''.join(part.zfill(3) for part in ip_parts) + '-' + str(port)
    return code


# Server configuration and UI elements
HOST = "0.0.0.0"  # Host address
PORT = 8000  # Port for the server to run on
httpServer = None

# Starts the server
def start_server():
    global httpServer
    
    password = secrets.token_urlsafe(8)[:8]  # Generate a random password
    
    # Set up the server and start it
    httpServer = socketserver.ThreadingTCPServer((HOST, PORT), ScreenCapture)
    httpServer.is_running = True
    httpServer.stream_password = password
    httpServer.active_connections = 0
    httpServer.update_connections = update_connection_count

    ip = get_private_ip()
    tv_code = generate_tv_code(ip, PORT)
    
    # Update the UI with server info
    status_label.configure(text="🟢 Server Running", text_color="#10AC84")
    ip_label.configure(text=f"{ip}:{PORT}")
    password_label.configure(text=password)
    tv_code_label.configure(text=tv_code)
    connections_label.configure(text="0")
    
    # Disable start button and enable stop button
    start_button.configure(state="disabled")
    stop_button.configure(state="normal")
    copy_tv_button.configure(state="normal")
    copy_pass_button.configure(state="normal")
    
    # Start the server
    httpServer.serve_forever()

# Updates the active connection count on the UI
def update_connection_count():
    if httpServer:
        connections = getattr(httpServer, 'active_connections', 0)
        connections_label.configure(text=str(connections))

# Starts the server in a new thread
def start_function():
    global httpServer
    if not httpServer:
        thread = threading.Thread(target=start_server, daemon=True)
        thread.start()

# Stops the server
def stop_function():
    global httpServer
    if httpServer:
        httpServer.is_running = False
        httpServer.shutdown()
        httpServer.server_close()
        httpServer = None
    
    # Update UI elements for stopping the server
    status_label.configure(text="🔴 Server Stopped", text_color="#EE5253")
    ip_label.configure(text="---")
    password_label.configure(text="---")
    tv_code_label.configure(text="---")
    connections_label.configure(text="0")
    
    start_button.configure(state="normal")
    stop_button.configure(state="disabled")
    copy_tv_button.configure(state="disabled")
    copy_pass_button.configure(state="disabled")

# Copy TV code to clipboard
def copy_tv_code():
    if httpServer:
        ip = get_private_ip()
        tv_code = generate_tv_code(ip, PORT)
        root.clipboard_clear()
        root.clipboard_append(tv_code)
        messagebox.showinfo("Copied!", f"TV Code copied to clipboard:\n{tv_code}")

# Copy password to clipboard
def copy_password():
    if httpServer:
        password = getattr(httpServer, 'stream_password', '')
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied!", f"Password copied to clipboard:\n{password}")

# CustomTkinter configuration for the GUI
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Main GUI setup with labels, buttons, and status display
root = ctk.CTk()
root.title("Screen Capture Server")
root.geometry("600x700")
root.resizable(False, False)

main_frame = ctk.CTkFrame(root, corner_radius=0)
main_frame.pack(fill="both", expand=True, padx=20, pady=20)

header = ctk.CTkLabel(main_frame, text="📡 Screen Capture Server", 
                      font=ctk.CTkFont(size=28, weight="bold"))
header.pack(pady=(20, 10))

# Status section
status_frame = ctk.CTkFrame(main_frame, corner_radius=10)
status_frame.pack(fill="x", padx=20, pady=10)

status_label = ctk.CTkLabel(status_frame, text="🔴 Server Stopped", 
                            font=ctk.CTkFont(size=18, weight="bold"),
                            text_color="#EE5253")
status_label.pack(pady=15)

# Control buttons for server management
button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
button_frame.pack(pady=20)

start_button = ctk.CTkButton(button_frame, text="▶ Start Server", 
                             command=start_function,
                             width=180, height=50,
                             font=ctk.CTkFont(size=16, weight="bold"),
                             fg_color="#fff",
                             hover_color="#0E9C75")
start_button.grid(row=0, column=0, padx=10)

stop_button = ctk.CTkButton(button_frame, text="⬛ Stop Server",
                            command=stop_function,
                            width=180, height=50,
                            font=ctk.CTkFont(size=16, weight="bold"),
                            fg_color="#EE5253",
                            hover_color="#D84445",
                            state="disabled")
stop_button.grid(row=0, column=1, padx=10)

# Footer with instructions
footer = ctk.CTkLabel(main_frame, text="⚠️ Keep this window open while streaming", 
                     font=ctk.CTkFont(size=11),
                     text_color="gray")
footer.pack(pady=(10, 20))

root.mainloop()
