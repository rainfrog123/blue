import pydirectinput
import time

def get_mouse_position():
    while True:
        x, y = pydirectinput.position()
        print(f"Current mouse position: ({x}, {y})")
        time.sleep(1)

get_mouse_position()
