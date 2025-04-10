import pyotp
import datetime

otp_secret = input("Enter your OTP secret: ").strip()
totp = pyotp.TOTP(otp_secret)
current_otp = totp.now()
print("Current OTP:", current_otp)
time_remaining = totp.interval - datetime.datetime.now().timestamp() % totp.interval
print("Time remaining:", int(time_remaining), "seconds")
