"""
# INFO:
The script scrapes the MITRE Website APT groups database,
and extracts the info for all the groups to a json file.

which can be queried by the query_json_apt.py script.
"""


import httpx
import asyncio
import re
from bs4 import BeautifulSoup
import json

url = "https://attack.mitre.org/groups/"


def extract_apt_details(html_content, url):
    soup = BeautifulSoup(html_content, "html.parser")

    # Extracting the APT group name (Title)
    title = soup.title.string if soup.title else None

    # Extracting APT group description from the description-body div
    description_div = soup.find("div", {"class": "description-body"})
    description = description_div.text.strip() if description_div else None

    # Extracting Techniques Used
    techniques = []
    techniques_table = soup.find(
        "table", {"class": "table techniques-used background table-bordered"}
    )
    if techniques_table:
        rows = techniques_table.find_all(
            "tr", {"class": "sub technique noparent enterprise"}
        )
        for row in rows:
            technique_name = row.find_all("td")[3].text.strip()
            technique_use = row.find_all("td")[4].text.strip()
            techniques.append(
                {"technique_name": technique_name, "technique_use": technique_use}
            )

    # Extracting Software
    software = []
    if techniques_table:
        rows = techniques_table.find_all(
            "tr", {"class": "sub technique noparent enterprise"}
        )
        for row in rows:
            technique_name = row.find_all("a")[2].text.strip()
            use_cell = row.find_all("td")[-1]
            software_links = use_cell.find_all("a")

            for link in software_links:
                if "/software/" in link["href"]:
                    software_name = link.text.strip()
                    software.append(
                        {
                            "software_name": software_name,
                            "associated_technique": technique_name,
                        }
                    )

    # Extracting References
    references = []
    ref_links = soup.find_all("a", {"class": "scite-citeref-number"}, href=True)
    for ref in ref_links:
        ref_text = ref.text.strip()
        ref_url = ref["href"].strip()
        references.append((ref_text, ref_url))

    json_ = {
        "apt_group_name": title,
        "description": description,
        "techniques_used": techniques,
        "software": software,
        "references": references,
        "url": url,
    }
    return json_


async def fetch_data():
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        if response.status_code == 200:
            groups = re.findall(r'<a\s+href="([^"]*?/group[^"]*)"', response.text)
        else:
            groups = []
        return groups


async def fetch_group_data(client, url):
    response = await client.get(url, follow_redirects=True)
    if response.status_code == 200:
        return response.content

    elif response.status_code == 301:
        # Handle 301 Redirect
        redirected_url = response.headers.get("Location")
        print(f"Redirected to: {redirected_url}")
        if redirected_url:
            response = await client.get(redirected_url)
            if response.status_code == 200:
                return response.headers
    return None


async def gather_data(groups):
    all_apt_details = []  # To store all APT group details

    async with httpx.AsyncClient() as client:
        for group in groups:
            if group.startswith("/groups/"):
                full_url = "https://attack.mitre.org" + group
                data = await fetch_group_data(client, full_url)
                if data:
                    apt_details = extract_apt_details(data, full_url)
                    all_apt_details.append(apt_details)
                else:
                    print(f"Error fetching data from: {full_url}")
            else:
                continue

    return all_apt_details


def make_hashable(d):
    if isinstance(d, (set, tuple, list)):
        return tuple([make_hashable(e) for e in d])
    if isinstance(d, dict):
        return tuple(sorted((k, make_hashable(v)) for k, v in d.items()))
    return d


def main():
    apts = asyncio.run(fetch_data())
    all_apt_details = asyncio.run(gather_data(apts))
    unique_dicts_set = {make_hashable(d) for d in all_apt_details}
    unique_dicts = [dict(d) for d in unique_dicts_set]

    # Combine all details into one JSON array
    combined_json = json.dumps(unique_dicts, indent=4)

    # Writing the json to a file
    with open("combined_apt_details.json", "w") as f:
        f.write(combined_json)


if __name__ == "__main__":
    main()
