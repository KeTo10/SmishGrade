""" 
SmishGrade Framework Implementation
-----------------------------------
Author: Kenny To
Date: November 13, 2025
Python Version: 3.12+

Description:
    SmishGrade is a smishing detection framework that utilizes a heuristic-based grading to analyze URL
    characteristics without content analysis.

Usage:
    python smishgrade.py

Input:
    The user is expected to input some file(s) containing URLs with each entry separated by a new line.
    The file(s) should be in the same directory as the SmishGrade.py file.
    It is worth noting that this code is meant to test the effectiveness of the framework, so the user will
    have to input the ground truth of each file, so that a performance analysis can be done afterwards.
    This means that each file should only contain all malicious or all benign URLs.

Output:
    The output is a .csv file containing the results of the framework with a numerical score,
    verdict (benign, suspicious, or malicious), and a list of all the heuristics that were trigger.
    There is also a .json file that will be created as a cache in case the WHOIS query crashes or repeats.

Dependencies:
    See requirement.txt (tldextract, python-whois)
"""

import ipaddress
import json
import time
import csv
from datetime import datetime, timezone
from urllib.parse import urlparse
import tldextract
import whois

# Heuristics/Characteristics variables and definitions
# Feel free to add to these lists based on new trends and findings.
# Doing so could improve effectiveness of the framework.

abused_TLD = {'.xyz', '.top','.link', '.club', '.online', '.live'}

suspicious_keywords = {'login', 'verify', 'secure', 'account', 'update', 'bank'}

# A dictionary of the heuristics and weights
# There is no particular order scheme required.
# The order used here makes it easier to reference in my paper
# The weights and heuristics can be adjusted for scoring
heuristic_weights = {
    'H1_Length' : 5,
    'H2_IP_Hostname' : 40,
    'H3_At_Symbol' : 10,
    'H4_Keywords' : 5,
    'H5_Subdomains' : 15,
    'H6_Abused_TLD' : 20,
    'H7_Domain_Age' : 50
}

# Any URL with a score of at least 1 is suspicious and any at least 20 is malicious
# For the purpose of classification, suspicious is categorized as malicious
# If the URL scores 0, it is benign
malicious_threshold = 20
suspicious_threshold = 1

# The .json file will be referenced in case of crashes or repetition for WHOIS queries
whois_cache = {}
whois_cache_file = 'whois_cache.json' 

def check_cache():
# This function will check if the cache file exists and reads it, otherwise create one
    global whois_cache
    try:
        with open(whois_cache_file, 'r') as f:
            whois_cache = json.load(f)
            print(f"Found {len(whois_cache)} entries from {whois_cache_file}.")
    except FileNotFoundError:
        print("No cache file found. Starting a new one.")
        whois_cache = {}
    except json.JSONDecodeError:
        print("Cache file is broken. Starting a new one.")
        whois_cache = {}

def save_cache():
# This function will write to the cache file to add new entries in case
# there are crashes between the processing of each file
    global whois_cache
    try:
        with open(whois_cache_file, 'w') as f:
            json.dump(whois_cache, f, indent=4)
        print(f"\nCache saved. There are {len(whois_cache)} entries")
    except Exception as error_message:
        print(f"Could not save cache: {error_message}")

def get_domain_age(domain):
# This function will check the cache to see if the domain has already been searched to avoid repetitions
# Otherwise perform a live query. Depending on the number of entries, this part can take awhile.
# Even if the lookup fails, the attempt will be logged to avoid repetition
    global whois_cache
    if domain in whois_cache:
        return whois_cache[domain]
    
    print (f"\n Looking up {domain}")
    try:
        time.sleep(1.5) # This is the time-consuming part, but it is necessary to avoid being rate-limited
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            origin_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age_in_days = (datetime.now(timezone.utc) - origin_date).days
            whois_cache[domain] = age_in_days
            return age_in_days
        else:
            whois_cache[domain] = -1
            return -1
    except Exception as e:
        print(f"Failed for {domain}: {e}")
        whois_cache[domain] = -1
        return -1
    
def analyze_url(url):
# This function will parse the URL and check for the heuristics
# Based on the heuristic(s) found, it will give a score and verdict
# Additionally, it will return the domain age and the heuristic(s) found
    heuristics_found = []
    total_score = 0
    
    if not url.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url

    try:
        parsed_url = urlparse(url_to_parse)
        hostname = parsed_url.hostname
        path = parsed_url.path
        extracted_domain = tldextract.extract(url_to_parse)
        main_domain = extracted_domain.top_domain_under_public_suffix
        subdomain = extracted_domain.subdomain
        tld = '.' + extracted_domain.suffix
        if not hostname:
            return 0, 'Error-No-Hostname', [], -1
    except Exception as error_message:
        print(f"Failed to parse {url}: {error_message}")
        return 0, 'Error-Parsing', [], -1
    
    if len(url) > 75: # Checking for excessive length
        total_score += heuristic_weights['H1_Length']
        heuristic_weights.append('H1_Length')

    try:
        ipaddress.ip_address(hostname)
        is_ip = True # Checking for IP Address
    except ValueError:
        is_ip = False
    
    if is_ip:
        total_score += heuristic_weights['H2_IP_Hostname']
        heuristics_found.append('H2_IP_Hostname')
  
    if '@' in url: # Checking for @ Symbol 
        total_score += heuristic_weights['H3_At_Symbol']
        heuristics_found.append('H3_At_Symbol')

    for keyword in suspicious_keywords: # Looping to check for keyword(s)
        if keyword in path.lower():
            total_score += heuristic_weights['H4_Keywords']
            heuristics_found.append('H4_Keywords')
            break # Ensures that this heuristic will only count once
    
    # Checking for excessive amounts of subdomains
    # 'www.Google.com' has 2 dots, so we check for >= 2
    if subdomain.count('.') >= 2:
        total_score += heuristic_weights['H5_Subdomains']
        heuristics_found.append('H5_Subdomains')

    if tld in abused_TLD: # Checking for abused TLD
        total_score += heuristic_weights['H6_Abused_TLD']
        heuristics_found.append('H6_Abused_TLD')
    
    # Performs a function call to check that domain age is less than 30 days
    domain_age = get_domain_age(main_domain)
    if 0 <= domain_age <= 30:
        total_score += heuristic_weights['H7_Domain_Age']
        heuristics_found.append('H7_Domain_Age')
    
    final_verdict = 'Benign'
    if total_score >= malicious_threshold: # at least 20 points
        final_verdict = 'Malicious'
    elif total_score >= suspicious_threshold: # at least 1 points
        final_verdict = 'Suspicious'

    return total_score, final_verdict, heuristics_found, domain_age

# Main
if __name__ == "__main__":
    print("SmishGrade Heuristic Analyzer")
    check_cache() # Check to see if cache needs to be generated
    output_csv_file='smishgrade_results.csv'
    try:
        with open(output_csv_file, 'a', newline='', encoding='utf-8') as f:
            csv_writer = csv.writer(f)

            f.seek(0,2) # Go to the end of the file and check the position
            if f.tell() == 0: # If the file is empty, position would be 0.
                print(f"Writing headers to new file: {output_csv_file}")
                csv_writer.writerow([
                    'URL',
                    'Ground_Truth',
                    'Score',
                    'Verdict',
                    'Heuristics_Found',
                    'Domain_Age_Days'
                ])
            
            while True:
                print("\n" + "="*50)
                print("Enter the .txt file to analyze (for example, 'tranco.txt')")
                print("Or type 'q' to [q]uit")
                input_file = input("> ")
                if input_file.lower() == 'q':
                    break # ends loop
        
                print("What is the ground truth for this file (is it 'malicious' or 'benign')?")
                ground_truth = input("> ").lower()
                if ground_truth not in ['malicious', 'benign']:
                    print("Invalid entry. Please type 'malicious' or 'benign'.")
                    continue # repeats loop

                print(f"\n Starting analysis on '{input_file}'")
                try:
                    with open(input_file, 'r') as text_file: # reads file for URLs
                        urls_to_test = [line.strip() for line in text_file if line.strip()]
                    print(f"{len(urls_to_test)} URLs were found.")

                    for n, url in enumerate(urls_to_test):
                        print(f"Processing {n+1}/{len(urls_to_test)}: {url[:70]}") # some formatting to remove clutter
                        score, verdict, heuristics, age = analyze_url(url) # call analyze function

                        csv_writer.writerow([ # write results into .csv
                            url,
                            ground_truth,
                            score,
                            verdict,
                            '|'.join(heuristics),
                            age
                        ])
                    print(f"Proccessed {input_file}")
                    save_cache()
                except FileNotFoundError:
                    print(f"File not found: {input_file}. Please check the name and directory")
                except Exception as error_message:
                    print(f"Critical error occurred: {error_message}")
    except Exception as error_message:
        print(f"An error occurred outside the loop: {error_message}")
    finally:
        save_cache()
        print("\n Analysis Complete. Exiting.")