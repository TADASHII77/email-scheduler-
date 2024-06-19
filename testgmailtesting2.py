from __future__ import print_function
import time
import pandas as pd
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import filedialog, messagebox
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ['https://mail.google.com/']

# user token storage
USER_TOKEN = 'token.json'

# application credentials (update the path if needed)
CREDENTIALS = r'C:\Users\yamim\Downloads\credentials.json\client_secret_963111725544-sgjeea5l7v1ltmnfhpvgq7bo4c4ofna8.apps.googleusercontent.com.json'

scheduled_email_id = None

def get_credentials() -> Credentials:
    creds = None
    if os.path.exists(USER_TOKEN):
        creds = Credentials.from_authorized_user_file(USER_TOKEN, SCOPES)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS, SCOPES)
        creds = flow.run_local_server(port=0)
        with open(USER_TOKEN, 'w') as token:
            token.write(creds.to_json())
    return creds

def send_email(host, port, subject, msg, sender, recipients, attachment_path=None):
    creds = get_credentials()
    access_token = creds.token

    # Create a multipart message
    message = MIMEMultipart()
    message['Subject'] = subject
    message['From'] = sender
    message['To'] = ', '.join(recipients)  # Join recipients into a comma-separated string

    # Add the message body
    message.attach(MIMEText(msg, 'plain'))

    # Add the attachment
    if attachment_path:
        part = MIMEBase('application', 'octet-stream')
        with open(attachment_path, 'rb') as attachment:
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename={os.path.basename(attachment_path)}',
        )
        message.attach(part)

    try:
        server = smtplib.SMTP(host, port)
        server.starttls()
        auth_string = 'user={}\1auth=Bearer {}\1\1'.format(sender, access_token)
        auth_string = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
        server.docmd('AUTH XOAUTH2 ' + auth_string)
        server.sendmail(sender, recipients, message.as_string())  # Use comma-separated recipients
        server.quit()
        print("Email sent successfully")
        messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email to {recipients}: {e}")
        messagebox.showerror("Error", f"Failed to send email to {recipients}: {e}")

def select_email_address_file():
    try:
        filepath = filedialog.askopenfilename()
        dataset = pd.read_csv(filepath, encoding='utf-8')
        recipients = dataset['email'].tolist()
        recipient_entry.delete(0, tk.END)
        recipient_entry.insert(0, ', '.join(recipients))
    except UnicodeDecodeError as e:
        print(f"UnicodeDecodeError: {e}")
        messagebox.showerror("Error", f"Failed to load recipients from CSV: UnicodeDecodeError - Try a different encoding.")
    except Exception as e:
        print(f"Error loading CSV: {e}")
        messagebox.showerror("Error", f"Failed to load recipients from CSV: {e}")
def select_attachment_file():
    try:
        filepath = filedialog.askopenfilename()
        attachment_entry.delete(0, tk.END)
        attachment_entry.insert(0, filepath)
    except Exception as e:
        print(f"Error selecting attachment file: {e}")
        messagebox.showerror("Error", f"Failed to select attachment file: {e}")

def update_current_time():
    current_time = time.strftime("%H:%M:%S", time.localtime())
    current_time_label.config(text=f"Current Time: {current_time}")
    root.after(1000, update_current_time)

def schedule_email():
    global scheduled_email_id
    sender = "2000rohitmehra@gmail.com"
    subject = subject_entry.get()
    
    recipients = recipient_entry.get().split(', ')
    attachment_path = attachment_entry.get()

    # Load the dataset
    try:
        dataset = pd.read_csv(attachment_path)
        # Select the first row and convert to string
        first_row = dataset.iloc[0].to_string()

        # Get desired send time from the user
        send_time_str = time_entry.get()
        if send_time_str:
            send_time = datetime.strptime(send_time_str, "%H:%M:%S").time()
            now = datetime.now()
            send_datetime = datetime.combine(now.date(), send_time)

            # If the send time is earlier than the current time, schedule for the next day
            if send_datetime < now:
                send_datetime += timedelta(days=1)

            # Calculate delay
            delay = (send_datetime - now).total_seconds()
            print(f"Email will be sent at: {send_datetime} (in {delay} seconds)")

            # Schedule the email
            scheduled_email_id = root.after(int(delay * 1000), lambda: send_email("smtp.gmail.com", 587, subject, first_row, sender, recipients, attachment_path))
        else:
            # Send immediately if no time is set
            send_email("smtp.gmail.com", 587, subject, first_row, sender, recipients, attachment_path)
    except Exception as e:
        print(f"Error loading CSV or sending email: {e}")
        messagebox.showerror("Error", f"Failed to load CSV or send email: {e}")

def cancel_scheduled_email():
    global scheduled_email_id
    if scheduled_email_id is not None:
        root.after_cancel(scheduled_email_id)
        scheduled_email_id = None
        print("Scheduled email canceled")
        messagebox.showinfo("Cancelled", "Scheduled email has been canceled.")
    else:
        messagebox.showinfo("No Scheduled Email", "There is no scheduled email to cancel.")

# Setup GUI
root = tk.Tk()
root.title("Email Scheduler")

# Styling
root.geometry("500x500")
root.configure(bg="#f0f0f0")

title_label = tk.Label(root, text="Email Scheduler", font=("Helvetica", 16, "bold"), bg="#f0f0f0")
title_label.pack(pady=10)

# Current Time Display
current_time_label = tk.Label(root, text="Current Time: ", font=("Helvetica", 12), bg="#f0f0f0")
current_time_label.pack()

# Update the current time every second
update_current_time()

# Time Entry
time_label = tk.Label(root, text="Enter the time to send the email (HH:MM:SS):", font=("Helvetica", 12), bg="#f0f0f0")
time_label.pack(pady=5)

time_entry = tk.Entry(root, font=("Helvetica", 12))
time_entry.pack()

# Recipient Entry
recipient_label = tk.Label(root, text="Recipient Email Addresses:", font=("Helvetica", 12), bg="#f0f0f0")
recipient_label.pack(pady=5)

recipient_entry = tk.Entry(root, font=("Helvetica", 12))
recipient_entry.pack()

# Subject Entry
subject_label = tk.Label(root, text="Enter the email subject:", font=("Helvetica", 12), bg="#f0f0f0")
subject_label.pack(pady=5)

subject_entry = tk.Entry(root, font=("Helvetica", 12))
subject_entry.pack()

# Attachment File Selection
attachment_label = tk.Label(root, text="Select attachment file:", font=("Helvetica", 12), bg="#f0f0f0")
attachment_label.pack(pady=5)

attachment_entry = tk.Entry(root, width=50, font=("Helvetica", 12))
attachment_entry.pack()

attachment_button = tk.Button(root, text="Browse", command=select_attachment_file, font=("Helvetica", 12), bg="#4CAF50", fg="white")
attachment_button.pack(pady=5)

# Select Email Address File Button
select_email_button = tk.Button(root, text="Select Email Address File", command=select_email_address_file, font=("Helvetica", 12), bg="#4CAF50", fg="white")
select_email_button.pack(pady=5)

# Schedule Email Button
schedule_button = tk.Button(root, text="Schedule Email", command=schedule_email, font=("Helvetica", 12), bg="#008CBA", fg="white")
schedule_button.pack(pady=10)

# Cancel Email Button
cancel_button = tk.Button(root, text="Cancel Scheduled Email", command=cancel_scheduled_email, font=("Helvetica", 12), bg="#f44336", fg="white")
cancel_button.pack(pady=10)

root.mainloop()
