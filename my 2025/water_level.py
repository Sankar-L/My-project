import RPi.GPIO as GPIO
import time
from datetime import datetime
from database import add_water_level_data  # Import the function to add data to the database

# Pin configuration
TRIG = 23
ECHO = 24
RELAY = 25

# Initialize GPIO
GPIO.setwarnings(False)  # Suppress warnings (optional)
GPIO.setmode(GPIO.BCM)
GPIO.setup(TRIG, GPIO.OUT)
GPIO.setup(ECHO, GPIO.IN)
GPIO.setup(RELAY, GPIO.OUT)

def measure_distance():
    # Send ultrasonic pulse
    GPIO.output(TRIG, True)
    time.sleep(0.00001)
    GPIO.output(TRIG, False)

    # Measure echo duration
    pulse_start = time.time()
    pulse_end = time.time()
    while GPIO.input(ECHO) == 0:
        pulse_start = time.time()
    while GPIO.input(ECHO) == 1:
        pulse_end = time.time()

    # Calculate distance in cm
    pulse_duration = pulse_end - pulse_start
    distance = (pulse_duration * 34300) / 2
    return distance

def control_pump(distance):
    if distance > 10:  # Low water level
        GPIO.output(RELAY, GPIO.HIGH)  # Turn on pump
    elif distance < 5:  # High water level
        GPIO.output(RELAY, GPIO.LOW)  # Turn off pump

def log_distance(distance):
    # Log the distance to the database
    sensor_id = "sensor_01"  # You can change this to a unique sensor ID
    add_water_level_data(sensor_id, distance)

try:
    while True:
        distance = measure_distance()
        print(f"Distance: {distance} cm")
        control_pump(distance)
        log_distance(distance)
        time.sleep(1)
except KeyboardInterrupt:
    print("Program interrupted")
finally:
    GPIO.cleanup()
    print("GPIO cleaned up")