import os

VERSION = "2.0.0"

os.system(f"pyinstaller --onefile --console --icon=assets/packet-shooter_icon.ico --name=\"PacketShooter-v{VERSION}\" p2pchat_tui.py")
# _6
