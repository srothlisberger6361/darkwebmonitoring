import pandas as pd
import requests
from datetime import datetime
import time
from bs4 import BeautifulSoup
from collections import defaultdict

# Function to check email leaks using LeakCheck API
def check_email_leak(email, api_key):
    url = f"https://leakcheck.io/api/public?check={email}&key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Function to check Have I Been Pwned for email with full breach model
def check_hibp(email, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        'hibp-api-key': api_key,
        'Accept': 'application/json',
        'User-Agent': 'LeakCheckerPro'  # Replace 'LeakCheckerPro' with your actual app name
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return []  # No breaches found
    else:
        print(f"HIBP API request failed with status code: {response.status_code}")
        return None

# Function to extract and clean description and references
def parse_description(description):
    soup = BeautifulSoup(description, 'html.parser')
    text = soup.get_text()
    links = [a['href'] for a in soup.find_all('a', href=True)]
    return text, "; ".join(links)

# Prompt user to input API keys
leakcheck_api_key = input("Please enter your LeakCheck API key: ")
hibp_api_key = input("Please enter your HaveIBeenPwned API key: ")

# Read the Excel file
input_file = 'clients_emails.xlsx'
df = pd.read_excel(input_file)

# Prepare the output data for each client
current_date = datetime.now().strftime("%Y-%m-%d")
one_year_ago = datetime.now() - pd.DateOffset(years=1)

def is_duplicate(existing_leaks, new_leak, new_date):
    new_leak_lower = new_leak.lower()
    for leak in existing_leaks:
        existing_leak, existing_date = leak.rsplit('(', 1)
        existing_leak = existing_leak.strip().lower()
        existing_date = existing_date.strip(')').lower()
        if new_leak_lower == existing_leak and new_date == existing_date:
            return True
    return False

def make_unique(data_leaked):
    # Create a set for unique entries
    unique_entries = set()
    # Dictionary to handle singular/plural forms
    singular_plural_map = defaultdict(list)

    for item in data_leaked:
        # Convert to lower case for comparison
        item_lower = item.lower()
        # Check singular/plural
        if item_lower.endswith('s'):
            singular_form = item_lower[:-1]
        else:
            singular_form = item_lower + 's'

        # Add to the map
        singular_plural_map[singular_form].append(item_lower)

    # Add the most common form to the unique entries
    for key, values in singular_plural_map.items():
        most_common = max(set(values), key=values.count)
        unique_entries.add(most_common)

    # Return the unique set as a list
    return list(unique_entries)

for _, row in df.iterrows():
    client_name = row['client']
    personal_emails = row['personal_emails'].split(',')
    corporate_emails = row['corporate_emails'].split(',')
    client_data = []
    breach_info_data = []

    print(f"Processing client: {client_name}")

    for email in personal_emails + corporate_emails:
        email = email.strip()
        print(f"Checking email: {email}")

        # Check with LeakCheck API
        leakcheck_result = check_email_leak(email, leakcheck_api_key)
        print(f"------LeakCheck result for {email}: {leakcheck_result}")

        if leakcheck_result and leakcheck_result["success"]:
            if leakcheck_result["found"] > 0:
                all_leaks = "; ".join([f"{leak['name']} ({leak['date']})" for leak in leakcheck_result["sources"]])
                data_leaked = set(leakcheck_result["fields"])
                # Skip entries with empty dates
                dated_sources = [source for source in leakcheck_result["sources"] if source["date"]]
                if dated_sources:
                    most_recent_leak = max(dated_sources, key=lambda x: datetime.strptime(x["date"], "%Y-%m"))
                    most_recent_leak_date = datetime.strptime(most_recent_leak["date"], "%Y-%m")
                    most_recent_leak_date_str = f"{most_recent_leak['name']}: {most_recent_leak_date.strftime('%Y-%m')}"
                else:
                    most_recent_leak_date_str = 'No Data'
                    most_recent_leak_date = None
            else:
                all_leaks, most_recent_leak_date_str, data_leaked = 'No Data', 'No Data', set()
                most_recent_leak_date = None
        else:
            all_leaks, most_recent_leak_date_str, data_leaked = 'No Data', 'No Data', set()
            most_recent_leak_date = None

        # Check with Have I Been Pwned API
        hibp_result = check_hibp(email, hibp_api_key)
        print(f"------HIBP result for {email}: {hibp_result}")

        if hibp_result is not None:
            hibp_leaks = [entry['Name'] for entry in hibp_result]
            for entry in hibp_result:
                hibp_leak = entry['Name']
                breach_date = datetime.strptime(entry['BreachDate'], "%Y-%m-%d").strftime("%Y-%m-%d")
                added_date = datetime.strptime(entry['AddedDate'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d")
                breach_description, references = parse_description(entry['Description'])
                hibp_data_classes = set(entry['DataClasses'])

                # Remove duplicates (e.g., 'password' and 'Password')
                data_leaked.update(set([d.lower() for d in hibp_data_classes]) - set([d.lower() for d in data_leaked]))

                if all_leaks == 'No Data':
                    all_leaks = f"{hibp_leak} ({breach_date})"
                else:
                    existing_leaks = all_leaks.split("; ")
                    if not is_duplicate(existing_leaks, hibp_leak, breach_date):
                        all_leaks += f"; {hibp_leak} ({breach_date})"

                # Get detailed breach info
                breach_info_data.append([hibp_leak, breach_date, added_date, breach_description, references])
                if most_recent_leak_date is None or datetime.strptime(breach_date, "%Y-%m-%d") > most_recent_leak_date:
                    most_recent_leak_date = datetime.strptime(breach_date, "%Y-%m-%d")
                    most_recent_leak_date_str = f"{hibp_leak}: {breach_date}"

        # Add a delay to avoid rate limiting
        time.sleep(7)

        # Check combined data_leaked set from both LeakCheck and HIBP
        print(f"------Combined data_leaked for {email}: {data_leaked}")

        # Remove duplicates in data_leaked
        unique_data_leaked = make_unique(data_leaked)

        # Check if 'password' is in the data_leaked set (case-insensitive)
        has_password = any("password" in d.lower() for d in unique_data_leaked)
        if True:
            if most_recent_leak_date and most_recent_leak_date > one_year_ago:
                risk_score = "High"
            elif has_password:
                risk_score = "High"
            else:
                risk_score = "Low"
        else:
            if has_password:
                risk_score = "High"
            else:
                risk_score = "Low"

        client_data.append([email, all_leaks, most_recent_leak_date_str, ", ".join(sorted(unique_data_leaked, key=str.lower)), risk_score])

    if client_data:
        # Create a DataFrame for the client's data with the required columns
        client_df = pd.DataFrame(client_data, columns=['email', 'Data Leak Name', 'Most Recent Leak Date', 'Data Historically Leaked', 'Risk Score'])

        # Fill any empty cells with 'N/A'
        client_df.fillna('No Data', inplace=True)

        # Sort the breach info data by date (most recent first)
        breach_info_data.sort(key=lambda x: datetime.strptime(x[1], "%Y-%m-%d"), reverse=True)

        # Save the output to a new Excel file named with the client's name and the current date
        with pd.ExcelWriter(f'{client_name}_DarkWebBreaches_{current_date}.xlsx') as writer:
            client_df.to_excel(writer, sheet_name='Leaked Data', index=False)

            # Create a DataFrame for the breach info data and save it to a new sheet
            if breach_info_data:
                breach_info_df = pd.DataFrame(breach_info_data, columns=['Data Leak Name', 'Breach Date', 'Date Added to Database', 'Description', 'References'])
                breach_info_df.to_excel(writer, sheet_name='Breach Details', index=False)

        print(f"Leaked credentials for {client_name} saved to {client_name}_DarkWebBreaches_{current_date}.xlsx")
    else:
        print(f"No leaked credentials found for {client_name}")

print('All reports generated.')
