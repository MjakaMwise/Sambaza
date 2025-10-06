# Sambaza Screen Share App

This Python project allows you to capture your screen and stream it over HTTP to a client. The server uses a password-based authentication system, where the client must supply the correct password to view the screen stream. The project utilizes `customtkinter` for the graphical user interface and `pyautogui` for taking screenshots.

## Features

- **Screen Capture Streaming:** Captures the screen in real-time and streams it to the client.
- **Password Protection:** Clients must provide a password to access the stream.
- **Client Authentication Page:** An HTML page is served for users to input the password.
- **TV Code Generation:** Generates a code to be used in Android TV apps to access the stream.

## Requirements

- Python 3.7 or higher
- `pyautogui` (for taking screenshots)
- `customtkinter` (for GUI elements)
- `hashlib` (for secure password hashing)

## Installation

1. Clone or download the repository.
2. Install required libraries:

```bash
pip install pyautogui customtkinter
