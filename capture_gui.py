import time
import threading
import mss
from Repo_Privacy_Guardian import GuiApp

def capture():
    # Wait for the GUI to render
    time.sleep(2)
    with mss.mss() as sct:
        sct.shot(output="gui_capture.png")
    
    print("Screenshot captured to gui_capture.png")
    app.root.quit()

app = GuiApp()
t = threading.Thread(target=capture, daemon=True)
t.start()
app.run()
