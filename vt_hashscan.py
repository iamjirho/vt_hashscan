#!/usr/bin/env python3

import requests
import csv
import time
import argparse
import signal
import sys

global apikey
apikey = 'yourapikey'

# Container to skip processed hashes when an error occured or the script was cancelled
processed_hashes = set()

# Catch user's CTRL + C and save the processed hashes. Add the processed hashes to the set above.
def sigint_handler(signal, frame):
    print("KeyboardInterrupt is caught")
    print("Enrichment partially completed. You can still try again")
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

def check_hash(hashes):
    url = f"https://www.virustotal.com/api/v3/files/{hashes}"
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    response = requests.get(url, headers=headers)

    # If no data is found in VT database
    if response.status_code == 404:
        return {
            'Hashes': hashes,
            'SHA256': 'Not Found',
            'SHA1': 'Not Found',
            'MD5': 'Not Found',
            'Vendors Tagged as Malicious': 'Not Found',
            'Total Vendors': 'Not Found',
            'SentinelOne': 'Not Found',
            'FileName': 'Not Found'
        }
    # Convert the response to python dictionary
    response_json = response.json()
    attributes = response_json['data']['attributes']

    # Extract filename
    filename = attributes.get('meaningful_name')

    # Extract hash values
    sha256_value = attributes.get('sha256')
    md5_value = attributes.get('md5')
    sha1_value = attributes.get('sha1')

    # Get VT score
    vt_score = attributes.get('last_analysis_stats')
    malicious = vt_score.get('malicious')
    suspicious = vt_score.get('suspicious')
    undetected = vt_score.get('undetected')
    harmless = vt_score.get('harmless')

    malicious_tags = int(malicious) + int (suspicious)
    total_vendor = int(malicious) + int(suspicious) + int(undetected) + int(harmless)

    # Get SentinelOne Results
    analysis_result = attributes.get('last_analysis_results')
    sentinelone_category = analysis_result.get('SentinelOne').get('category')

    return {
        'Hashes': hashes,
        'SHA256': sha256_value,
        'SHA1': sha1_value,
        'MD5': md5_value,
        'Vendors Tagged as Malicious': malicious_tags,
        'Total Vendors': total_vendor,
        'SentinelOne': sentinelone_category,
        'FileName': filename
    }

# Commandline GUI
parser = argparse.ArgumentParser(description="VT Hash Search")
parser.add_argument('-f', '--file', required=True, help="Input CSV file path containing the hashes")
parser.add_argument('-o', '--output', required=True, help="Output CSV file for vetted hashes")
args = parser.parse_args()

input_file = args.file
output_file = args.output

# Read CSV file
try:
    with open(input_file, 'r', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        hash_list = list(reader) #Transform into a list
    
    # Due to VT 500 request per day. It needs to check the number of hashes first
    if len(hash_list) > 500:
        print('Number of hash exceeds 500. Only the first 500 will be checked OR until it exceeds API limit')
        hash_list = hash_list[:500]
    
    # Load previously processed hashes after user canceled the script during execution
    try:
        with open(output_file, 'r', encoding='utf-8') as outfile:
            existing_hashes = csv.DictReader(outfile)
            for row in existing_hashes:
                processed_hashes.add(row['Hashes'])
    except FileNotFoundError:
        pass

    # Output CSV file with headers
    with open(output_file, 'a', newline='', encoding='utf-8') as outfile:
        #Write Header
        fieldnames = [
            'Hashes',
            'SHA256',
            'SHA1',
            'MD5',
            'Vendors Tagged as Malicious',
            'Total Vendors',
            'SentinelOne',
            'FileName'
        ]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)

        # If empty. Writes the CSV header. If not empty, skip writing the header column.
        if not processed_hashes:
            writer.writeheader()

        # Enrich hashes
        for value in hash_list:
            try:
                column_name = 'Hashes'
                hashes = value[column_name]

                if hashes in processed_hashes:
                    print(f"Skipping processed hash {hashes}")
                    continue

                print(f'Processing {hashes}...')
                data = check_hash(hashes)
                writer.writerow(data)

                processed_hashes.add(hashes) #Add processed hashes
                
                time.sleep(15) # To comply with VT's 4 request per minute policy

            except KeyError:
                print(f"The CSV does not contain {column_name} header.")
                break
            except requests.exceptions.RequestException as e:
                print(f"Unexpected error occured: {e}")
                print(f"Maximum API request limit might be depleted")
                break
            except Exception as e:
                print(f"For some reason, an error occured {e}")

except FileNotFoundError:
    print("Specified file was not found")
except Exception as e:
    print(f"An unexpected error occured: {e}")
finally:
    print('Enrichment Completed')
