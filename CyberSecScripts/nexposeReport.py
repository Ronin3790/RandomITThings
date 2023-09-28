import requests
import json

# Nexpose API configuration
nexpose_api_url = 'https://your-nexpose-instance:port/api/3'
nexpose_api_key = 'your-api-key'
site_id = 'site-id'
email_recipient = 'recipient@example.com'

# Authenticate with Nexpose API
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Basic {nexpose_api_key}'
}

# Step 1: Select the site
def select_site(site_id):
    site_url = f'{nexpose_api_url}/sites/{site_id}'
    
    try:
        response = requests.get(site_url, headers=headers)
        response.raise_for_status()
        site_data = response.json()
        return site_data
    except requests.exceptions.RequestException as e:
        print(f"Error selecting site: {e}")
        return None

# Step 2: Generate a report for the selected site
def generate_report(site_id):
    report_url = f'{nexpose_api_url}/reports'
    report_data = {
        "site": {
            "id": site_id
        },
        "reportConfig": {
            "format": "pdf",  # You can change the format to your preference
            "template": "basic"
        }
    }

    try:
        response = requests.post(report_url, headers=headers, data=json.dumps(report_data))
        response.raise_for_status()
        report_info = response.json()
        return report_info
    except requests.exceptions.RequestException as e:
        print(f"Error generating report: {e}")
        return None

# Step 3: Send the report via Nexpose email
def send_report_via_email(report_id, email_recipient):
    email_url = f'{nexpose_api_url}/reports/{report_id}/send'
    email_data = {
        "recipients": [email_recipient]
    }

    try:
        response = requests.post(email_url, headers=headers, data=json.dumps(email_data))
        response.raise_for_status()
        print(f"Report sent to {email_recipient}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending report via email: {e}")

if __name__ == "__main__":
    selected_site = select_site(site_id)
    
    if selected_site:
        report_info = generate_report(site_id)
        
        if report_info:
            report_id = report_info['id']
            send_report_via_email(report_id, email_recipient)
