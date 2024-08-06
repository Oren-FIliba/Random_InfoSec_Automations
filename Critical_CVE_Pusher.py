import nvdlib
import time
import requests
import csv
import re
import datetime
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import os

# Set your Slack token and channel ID as environment variables or directly in the script
s_token = 'SLACK-ACCESS-TOKEN'
c_id = 'CHANNEL ID'

today = datetime.datetime.now()
last_week = (datetime.datetime.now() - datetime.timedelta(days=7))
critical_software_list = ["microsoft", "windows", "linux", "mac os", "kubernetes", "azure", "amazon", "aws", "gcp", "vmware", "palo alto", "global protect", "panorama","pan-os", "fortigate", "esxi", "docker", "apple", "rce", "remote code execution"]
year = datetime.datetime.now().year
#year = '2024'
csv_file_path = rf'C:\Cases\CVES_Database.csv'
github_urls = []
ids = []
published = []
descriptions = []
nist_url = []
cve_year = []
column_cve_values = []

def extract_column_cve(file_path):

    with open(file_path, newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            if row:  # Ensure the row is not empty
                column_cve_values.append(row[0])  # Append the first column's value
def get_cves():

    r = nvdlib.searchCVE(pubStartDate = last_week, pubEndDate = today, cvssV3Severity='Critical')
    for i in r:
        if str(year) in i.id:
            if i.id not in column_cve_values:
                description = i.descriptions[0].value
                cve_id = str(i.id)
                for software in critical_software_list:
                    if software.lower() in description.lower() or software.lower() in i.sourceIdentifier.lower():
                        cve_id = str(i.id + " critical_software")
                        break
                ids.append(cve_id)
                nist_url.append(i.url)
                published.append(re.findall(r'\d{4}-\d{2}-\d{2}', i.published)[0])
                descriptions.append(str(description).replace('\n',''))
                cve_year.append(re.findall(r'\d{4}', i.published)[0])
            else:
                continue
        else:
            continue

def fetch_github_github_urls(cve_id):

    github_github_urls_dict = {}

    api_url = f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}"
    response = requests.get(api_url)

    if response.status_code == 200:
        data = response.json()
        if "pocs" in data and data["pocs"]:
            github_github_urls = [poc["html_url"] for poc in data["pocs"]]
        else:
            github_github_urls = "No exploits Found"
        github_urls.append(github_github_urls)

def write_to_csv(info):

    with open(csv_file_path, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(info)

def send_update_slack(slack_token, channel_id, update):
    client = WebClient(token=slack_token)
    try:
        client.chat_postMessage(channel=channel_id, text=update, mrkdwn=True)

    except SlackApiError as e:
        print(f"Error posting message: {e}")

def upload_csv_to_slack(slack_token, channel_id, file_path):
    client = WebClient(token=slack_token)
    try:
        response = client.files_upload_v2(
            channels=channel_id,
            file=file_path,
            title=f"CSV File: {os.path.basename(file_path)} - {today}"
        )
        assert response["file"]  # the uploaded file
        print(f"[+] File uploaded successfully: {response['file']['id']}")
    except SlackApiError as e:
        print(f"Error uploading file: {e.response['error']}")

def main():
    start_time = time.time()
    extract_column_cve(csv_file_path)
    get_cves()
    message = f"*TIME FOR THE WEEK `CRITICAL` CVEs ({last_week.strftime('%Y-%m-%d')} - {today.strftime('%Y-%m-%d')})*\n\n\n"

    for cve in ids:
        fetch_github_github_urls(cve)
        info = [str(cve.replace(" critical_software", "")), cve_year[ids.index(cve)], published[ids.index(cve)], nist_url[ids.index(cve)], github_urls[ids.index(cve)]]
        write_to_csv(info)

    if len(ids) != 0:
        for i in range(0, len(ids)):
            if "critical_software" in ids[i]:
                id = ids[i].replace("critical_software", "")
                message += f"*{i+1})* {id}  `CRITICAL SOFTWARE !`\n\n  *`URL`:* {nist_url[i]}\n  *`Description`:* {descriptions[i]} \n  *`Published`:* {published[i]}\n\n--------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"
            else:
                message += f"*{i+1})* {ids[i]}\n\n  *`URL`:* {nist_url[i]}\n  *`Description`:* {descriptions[i]} \n  *`Published`:* {published[i]}\n\n--------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

        send_update_slack(s_token, c_id, message)
        upload_csv_to_slack(s_token, c_id, csv_file_path)

    else:
        message += "[+] No critical CVEs found"
        send_update_slack(s_token, c_id, message)

        print("no CVEs found")

    print("[+] Done!")
    end_time = time.time()
    print(f"[+] Time taken: {end_time - start_time} seconds")

if __name__ == "__main__":
    main()