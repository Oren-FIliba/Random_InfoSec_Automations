import time
import feedparser
import iocextract
from tags import *  # Tags being searched
from whitelist import *  # Whitelist URLs, domains, etc
from datetime import datetime
import csv
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import re

# Colours

RED = "\033[91m"
ENDC = "\033[0m"
GREEN = "\0333[1;32m"
WHITE = "\033[1m"
BOLD = "\033[01m"
BLUE = "\033[94m"
ORANGE = "\033[38;5;202m"
# Parameters
rss_url = "https://rss.app/feeds/<YOUR RSS FEED>"  # RSS feed url,change this
csv_file = r"file_path\to\Tweet_Feed.csv"  # path to csv, change this
log_file = r"path\to\run_log.txt"  # path to log file, change this
s_token = "xxx-slack-bot-token-xxxx"  # Change this
c_id = "<Slack Channel ID>"  # Change this

# Fetch and parse the RSS feed
feed = feedparser.parse(rss_url)


# Function to check if an IOC value already exists in the CSV
def ioc_exists(ioc_value):
    if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
        with open(csv_file, mode="r") as iocs_file:
            iocs_reader = csv.reader(iocs_file, delimiter=",")
            for row in iocs_reader:
                if len(row) > 3 and ioc_value == row[3]:
                    return True
    return False


def send_update_slack(slack_token, channel_id, update):
    client = WebClient(token=slack_token)
    try:
        client.chat_postMessage(channel=channel_id, text=update, mrkdwn=True)

    except SlackApiError as e:
        print(f"Error posting message: {e}")


def upload_csv_to_slack(slack_token, channel_id, file_path, title_name):
    client = WebClient(token=slack_token)
    try:
        response = client.files_upload_v2(
            channels=channel_id,
            file=file_path,
            title=f"${title_name}: {os.path.basename(file_path)} - {datetime.today()}",
        )
        assert response["file"]  # the uploaded file
        print(f"[+] File uploaded successfully: {response['file']['id']}")
    except SlackApiError as e:
        print(f"Error uploading file: {e.response['error']}")


# Get IOCs from RSS feed
new_urls = []
new_ips = []
new_sha256 = []
new_md5 = []

for entry in feed.entries:
    # Check if the user is in whitelist
    author = entry.get("author", "")

    if author in whitelist_users:
        continue

    # Get the entry's content
    content = entry.get("summary", "")

    urls = iocextract.extract_urls(content, refang=True)
    ips = iocextract.extract_ips(content, refang=True)
    sha256s = iocextract.extract_sha256_hashes(content)
    md5s = iocextract.extract_md5_hashes(content)

    # Get entry's date
    entry_date = entry.get("published_parsed", datetime.now().timetuple())
    entry_date = datetime.fromtimestamp(datetime(*entry_date[:6]).timestamp())

    # Get entry's link
    entry_link = entry.get("link", "")

    # Get URLs
    for url in urls:
        if (
            url not in new_urls
            and not url.startswith("https://t.co")
            and "twitter.com/" not in url
            and url not in whitelist_urls
        ):
            if "<" in url:
                url = re.sub("<.*", " ", url)
            if not ioc_exists(url):
                entry_date_str = entry_date.strftime("%Y-%m-%d %H:%M:%S")
                ioc_type = "url"
                ioc_value = url

                entry_tags = ""
                n_tags = 0
                for tag in tags:
                    if tag.lower() in content.lower():
                        if n_tags == 0:
                            entry_tags = tag

                        else:
                            try:
                                re_tag = (
                                    str(
                                        set(
                                            re.findall(
                                                r"#[a-z0-9$&+,:;=_?@#|~.^*()%!-]{2,15}",
                                                str(content.lower()),
                                            )
                                        )
                                    )
                                    .replace("'", "")
                                    .replace(",", " ")
                                    .replace("{", "")
                                    .replace("}", "")
                                )
                                # print(re_tag)
                                if re_tag == "set()":
                                    re_tag = ""
                            except Exception as e:
                                re_tag = ""
                            entry_tags = entry_tags + " " + re_tag
                            entry_tags = " ".join(set(entry_tags.lower().split()))

                        n_tags += 1

                row = [
                    entry_date_str,
                    author,
                    ioc_type,
                    ioc_value,
                    entry_tags,
                    entry_link,
                ]

                with open(csv_file, mode="a", newline="") as iocs_file:
                    iocs_writer = csv.writer(
                        iocs_file,
                        delimiter=",",
                        quotechar='"',
                        quoting=csv.QUOTE_MINIMAL,
                    )
                    iocs_writer.writerow(row)

                new_urls.append(url)

    # Get IPs
    for ip in ips:
        if (
            ip not in new_ips
            and ip not in whitelist_ips
            and re.findall(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
        ):
            if not ioc_exists(ip):
                entry_date_str = entry_date.strftime("%Y-%m-%d %H:%M:%S")
                ioc_type = "ip"
                ioc_value = ip

                entry_tags = ""
                n_tags = 0
                for tag in tags:
                    if tag.lower() in content.lower():
                        if n_tags == 0:
                            entry_tags = tag

                        else:
                            try:
                                re_tag = (
                                    str(
                                        re.findall(
                                            r"#[a-z0-9$&+,:;=_?@#|~.^*()%!-]{2,15}",
                                            str(content.lower()),
                                        )
                                    )
                                    .replace("[", "")
                                    .replace("]", "")
                                    .replace("'", "")
                                    .replace(",", " ")
                                )
                                print(re_tag)
                                if re_tag == "set()":
                                    re_tag = ""
                            except Exception as e:
                                re_tag = ""
                            entry_tags = entry_tags + " " + re_tag
                            entry_tags = " ".join(set(entry_tags.lower().split()))
                        n_tags += 1

                row = [
                    entry_date_str,
                    author,
                    ioc_type,
                    ioc_value,
                    entry_tags,
                    entry_link,
                ]

                with open(csv_file, mode="a", newline="") as iocs_file:
                    iocs_writer = csv.writer(
                        iocs_file,
                        delimiter=",",
                        quotechar='"',
                        quoting=csv.QUOTE_MINIMAL,
                    )
                    iocs_writer.writerow(row)

                new_ips.append(ip)

    # Get SHA256s
    for sha256 in sha256s:
        if sha256 not in new_sha256:
            if not ioc_exists(sha256):
                entry_date_str = entry_date.strftime("%Y-%m-%d %H:%M:%S")
                ioc_type = "sha256"
                ioc_value = sha256

                entry_tags = ""
                n_tags = 0
                for tag in tags:
                    if tag.lower() in content.lower():
                        if n_tags == 0:
                            entry_tags = tag

                        else:
                            try:
                                re_tag = (
                                    str(
                                        set(
                                            re.findall(
                                                r"#[a-z0-9$&+,:;=_?@#|~.^*()%!-]{2,15}",
                                                str(content.lower()),
                                            )
                                        )
                                    )
                                    .replace("'", "")
                                    .replace(",", " ")
                                    .replace("{", "")
                                    .replace("}", "")
                                )
                                print(re_tag)
                                if re_tag == "set()":
                                    re_tag = ""
                            except Exception as e:
                                re_tag = ""
                            entry_tags = entry_tags + re_tag
                            entry_tags = " ".join(set(entry_tags.lower().split()))

                        n_tags += 1

                row = [
                    entry_date_str,
                    author,
                    ioc_type,
                    ioc_value,
                    entry_tags,
                    entry_link,
                ]

                with open(csv_file, mode="a", newline="") as iocs_file:
                    iocs_writer = csv.writer(
                        iocs_file,
                        delimiter=",",
                        quotechar='"',
                        quoting=csv.QUOTE_MINIMAL,
                    )
                    iocs_writer.writerow(row)

                new_sha256.append(sha256)

    # Get MD5s
    for md5 in md5s:
        if md5 not in new_md5:
            if not ioc_exists(md5):
                entry_date_str = entry_date.strftime("%Y-%m-%d %H:%M:%S")
                ioc_type = "md5"
                ioc_value = md5

                entry_tags = ""
                n_tags = 0
                for tag in tags:
                    if tag.lower() in content.lower():
                        if n_tags == 0:
                            entry_tags = tag
                        else:
                            try:
                                re_tag = (
                                    str(
                                        set(
                                            re.findall(
                                                r"#[a-z0-9$&+,:;=_?@#|~.^*()%!-]{2,15}",
                                                str(content.lower()),
                                            )
                                        )
                                    )
                                    .replace("'", "")
                                    .replace(",", " ")
                                    .replace("{", "")
                                    .replace("}", "")
                                )
                                print(re_tag)
                                if re_tag == []:
                                    re_tag = ""
                            except Exception as e:
                                re_tag = ""
                            entry_tags = entry_tags + "" + re_tag
                            # remove duplicates from entry_tags not case-sensitive and be a string
                            entry_tags = " ".join(set(entry_tags.lower().split()))

                        n_tags += 1

                row = [
                    entry_date_str,
                    author,
                    ioc_type,
                    ioc_value,
                    entry_tags,
                    entry_link,
                ]

                with open(csv_file, mode="a", newline="") as iocs_file:
                    iocs_writer = csv.writer(
                        iocs_file,
                        delimiter=",",
                        quotechar='"',
                        quoting=csv.QUOTE_MINIMAL,
                    )
                    iocs_writer.writerow(row)

                new_md5.append(md5)

# Print info in terminal and insert to run_log.txt file with date of execution

message = ""
print(40 * "=")

print(GREEN + "[+] IOCs added:" + ENDC)
message += "\n[+] *TweetFeed_Rss IOCs added:*\n\n"
print("\t- URLs: " + str(len(new_urls)))
message += "\t- `URLs`: " + str(len(new_urls)) + "\n"
print("\t- IPs: " + str(len(new_ips)))
message += "\t- `IPs`: " + str(len(new_ips)) + "\n"
print("\t- SHA256: " + str(len(new_sha256)))
message += "\t- `SHA256`: " + str(len(new_sha256)) + "\n"
print("\t- MD5: " + str(len(new_md5)))
message += "\t- `MD5`: " + str(len(new_md5)) + "\n\n"
print(40 * "=")
print("Finished at: " + time.strftime("%Y-%m-%d %H:%M:%S"))
message += "\n`Finished at`: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n\n"

with open(log_file, "a") as f:
    f.write("[+] Ran at: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
    f.write("[+] TweetFeed_Rss - IOCs added:" + "\n")
    f.write("\t- URLs: " + str(len(new_urls)) + "\n")
    f.write("\t- IPs: " + str(len(new_ips)) + "\n")
    f.write("\t- SHA256: " + str(len(new_sha256)) + "\n")
    f.write("\t- MD5: " + str(len(new_md5)) + "\n")
    f.write((40 * "=") + "\n\n\n")

send_update_slack(s_token, c_id, message)
upload_csv_to_slack(s_token, c_id, csv_file, "Tweet_Feed_IOC CSV")
