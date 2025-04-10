import pyotp
import datetime

otp_secret = input("Enter your OTP secret: ").strip()
totp = pyotp.TOTP(otp_secret)
current_otp = totp.now()
print("Current OTP:", current_otp)
time_remaining = totp.interval - datetime.datetime.now().timestamp() % totp.interval

# We add 30 seconds to the computed remaining time because our server is configured to accept
# an OTP from the previous time period (using valid_window=1). This effectively extends the OTP's
# acceptability by an extra full interval (30 seconds), providing users more time to input the OTP if needed.
print("Time remaining:", int(time_remaining)+30, "seconds")
