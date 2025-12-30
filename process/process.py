import pandas as pd
import requests

majestic_df = pd.read_csv("majestic_million.csv")

legitimate_urls = ["https://" + domain for domain in majestic_df["Domain"].tolist()]
legitimate_labels = ["legitimate"] * len(legitimate_urls)  
    
verified_df = pd.read_csv("verified_online.csv")

phishing_urls = verified_df["url"].tolist()
phishing_labels = ["phishing"] * len(phishing_urls) 
    
all_urls = legitimate_urls + phishing_urls
all_labels = legitimate_labels + phishing_labels

df = pd.DataFrame({
    "url": all_urls,
    "label": all_labels
})
print(f"Created DataFrame with {len(df)} rows.")

send_url_endpoint = "http://send_url_container:8000/dispatch"
payload = {"urls": all_urls}
headers = {'Content-Type': 'application/json'}

try:
    print(f"Sending URLs to {send_url_endpoint}...")
    response = requests.post(send_url_endpoint, json=payload, headers=headers, timeout=300)
    if response.status_code == 200:
        print(f"Successfully sent to {send_url_endpoint}: {response.json()}")
    else:
        print(f"Failed to send to {send_url_endpoint}. Status code: {response.status_code}, Response: {response.text}")
except Exception as e:
    print(f"Error sending to {send_url_endpoint}: {e}")
