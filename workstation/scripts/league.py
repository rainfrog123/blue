import pydirectinput
import time

# Define the positions for clicks (x, y)
click_position = (1445, 214)
click_2_position = (1502, 369)
click_3_position = (945, 476)

# Delay before actions
action_delay = 1  # seconds
click_duration = 0.1  # Click duration in seconds

time.sleep(2)  # Initial delay before starting the script

try:
    while True:  # Start an infinite loop
        # First click sequence
        pydirectinput.moveTo(*click_position)
        time.sleep(action_delay)

        pydirectinput.mouseDown(button='right')
        time.sleep(0.2)  # Hold the right-click for a longer duration
        pydirectinput.mouseUp(button='right')

        time.sleep(action_delay)

        # Second click sequence
        pydirectinput.moveTo(*click_2_position)
        time.sleep(action_delay)

        pydirectinput.mouseDown(button='left')
        time.sleep(0.2)  # Hold the left-click for a longer duration
        pydirectinput.mouseUp(button='left')

        time.sleep(action_delay)

        # Third click sequence
        pydirectinput.moveTo(*click_3_position)
        time.sleep(action_delay)

        pydirectinput.mouseDown(button='left')
        time.sleep(0.2)  # Hold the left-click for a longer duration
        pydirectinput.mouseUp(button='left')

        time.sleep(action_delay)  # Wait before repeating the loop

except KeyboardInterrupt:
    print("Script terminated by user.")
