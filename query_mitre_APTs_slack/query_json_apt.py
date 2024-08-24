'''
This script querys the json file that was created with the mitre_apt_details_to_json.py,
in order to extract information on desired APT group, their techniques and softwares.

Usage :
    python3 query_json_apt <APTname> - this will create an <APTNAME>.md report and upload it to the slack channel
    python3 query_json_apt <APTname>,s+ - the 's+' means only to extract the softwares, so it will send a message in slack about the APT softwares.
    python3 query_json_apt <APTname>,t+ - the 's+' means only to extract the techniques, and will send a message  in slack about the APT techniques.
    python3 query_json_apt all - will upload the json file for all the apts to slack.

NOTE: Recommended to configure this commands as a bot /command in slack.
'''


import json
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import os
from datetime import datetime
import re
import sys
import warnings

warnings.filterwarnings("ignore", category=UserWarning, message="Although the channels parameter is still supported")


def search(keywords, contents):
    params = keywords
    file_path = f"C:\\Users\\Oren\\PycharmProjects\\Random_Dev\\{params[0]}_report.md"
    results = ""

    for json in contents:
        if params[0] in json["apt_group_name"]:
            if len(params) == 1:
                print("helloo11")
                results += f" # {params[0]} Report\n"
                results += f" =================\n\n"
                results += f" \\\\ Mitre URL = {json["url"]}\n\n"
                results += f" \\\\ Info:\n\n\t - {json["description"]}\n\n"
                results += f" ## Techniques Used: \n"
                results += f" ===================\n\n"
                for teq in json["techniques_used"]:
                    results += f"\\\\ {teq[0][1]}: \n\t  - {teq[1][1]}\n\n"
                results += f" \n\n ## Software Used:\n"
                results += f" ======================\n\n"
                for soft in json["software"]:
                    results += f"\\\\ {soft[1][1]} : \n\t - associated_techniques: {soft[0][1]}\n\n"
                with open(file_path, "w") as f:
                    f.write(re.sub(r'\[\d+\]', '', results))

            if "t+" in params:
                results += f" # `{params[0]} - Techniques`\n"
                results += f" =================\n\n"
                results += f" `Mitre URL` -  {json["url"]}\n\n"
                results += f" `Info`:\n\n\t - {json["description"]}\n\n"
                results += f" ## Techniques Used: \n"
                results += f" ===================\n\n"
                for teq in json["techniques_used"]:
                    results += f" \t# `{teq[0][1]}`: \n\t\t  - {teq[1][1]}\n\n"

            if "s+" in params:
                results += f" # `{params[0]} - Software`\n"
                results += f" =================\n"
                results += f" `Mitre URL` -  {json["url"]}\n\n"
                results += f" `INFO`:\n\n\t - {json["description"]}\n\n"
                results += f" \n\n ## `Software Used`:\n"
                results += f" ======================\n\n"
                for soft in json["software"]:
                    results += f"\t# `{soft[1][1]} `: \n\t\t - associated_techniques: {soft[0][1]}\n\n"
        else:
            continue
        return file_path, results


def send_update_slack(slack_token, channel_id, update):
        client = WebClient(token=slack_token)
        try:
            client.chat_postMessage(channel=channel_id, text=update, mrkdwn=True)

        except SlackApiError as e:
            print(f"Error posting message: {e}")


def upload_file_to_slack(slack_token, channel_id, file_path, title_name):
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


def main():
    s_token = "xoxb-SLACK-BOT-TOKEN"
    c_id = "<SLACK CHANNEL ID >"

    apt_json_file = (
        r"C:\\Users\\Oren\\PycharmProjects\\Random_Dev\\combined_apt_details.json"
    )

    with open(apt_json_file, "r") as file:
        json_contents = json.loads(file.read())

    search_word = sys.argv[1]
    search_list = search_word.split(",")

    if search_word == "all":
        upload_file_to_slack(s_token, c_id, apt_json_file, "Mitre_APT_data.json")
    else:
        result = search(search_list, json_contents)
        if len(search_list) == 1:
            try:
                upload_file_to_slack(s_token, c_id, result[0], f"{search_list[0]}_Report.md")
                os.remove(result[0])
            except Exception as e:
                error_file =  f"`Error` : No APT group was found by the name - *{search_list[0]}*"
                send_update_slack(s_token, c_id,error_file)
        else:
            if result == None:
                try:
                    error_message =  f"`Error` : No APT group was found by the name - *{search_list[0]}*"
                    send_update_slack(s_token, c_id,error_message)
                except Exception as e:
                    pass
            else:
                if result[1] == '':
                    e = f"`Error`: Wrong command arguments, check your command - `{search_word}`"
                    send_update_slack(s_token, c_id, e)
                else:
                    print("mamno")
                    update = send_update_slack(s_token, c_id,re.sub(r'\[\d+\]', '' ,str(result[1])))


if __name__ == "__main__":
    main()
