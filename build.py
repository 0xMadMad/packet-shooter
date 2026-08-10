import os

VERSION = "1.0.0"

os.system(f"pyinstaller --onefile --console --icon=assets/packet-shooter_icon.ico --name=\"Packet Shooter v{VERSION}\" p2pchat_tui.py")
# _6
