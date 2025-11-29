import requests

server_ip = "26.178.118.134"  # IP السيرفر على Radmin VPN
url = f"http://{server_ip}:8000/upload_csv"

# Updated file path
file_path = r"D:\UNI\Project\suhibe\NEW_Dummy_Data_shuffled.csv"

try:
    with open(file_path, "rb") as f:
        files = {"file": (file_path.split("\\")[-1], f, "text/csv")}
        response = requests.post(url, files=files, timeout=10)  # added timeout

    # Check if the response is valid JSON
    if response.headers.get("Content-Type") == "application/json":
        print(response.json())
    else:
        print("Server response:", response.text)

except requests.exceptions.ConnectTimeout:
    print("Connection timed out. Make sure the server is accessible via Radmin VPN.")
except requests.exceptions.RequestException as e:
    print("Request failed:", e)
except FileNotFoundError:
    print(f"File not found: {file_path}")
