"""Parses a folder of emails sent by Thinkst canarytoken and creates a
.csv that corresponds to the csv that is directly downloadable from the token page
"""

import csv
import os
import argparse
import logging
import quopri
import ipaddress
from datetime import datetime
from collections import Counter

import requests
from bs4 import BeautifulSoup

import analysis

class TokenHitEnrichmentClass:
    """Convenience class to store data used for lookups that
    we need globally     and only want to initialize once"""
    tor_node_list = []
    url_of_tor_node_list = "https://check.torproject.org/torbulkexitlist"

    url_of_ipinfo = "https://ipinfo.io/{ip}?token={token}"
    ipinfo_api_key = ADD_YOUR_API_KEY

class TokenHit:
    """Corresponds to data from a single email"""
    csv_header = ["Timestamp", "src_ip", "input_channel", "geo_info",
            "is_tor_relay", "referer", "location", "useragent"]

    def __init__(self, timestamp, src_ip, input_channel, useragent,
        geo_info=None, is_tor_relay=None, referer=None, location=None):
        # Order as in CSV
        # Taken from email
        self.timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S (%Z)")
        self.src_ip = src_ip
        self.input_channel = input_channel

        # Lookups necessary
        if geo_info is None:
            self.get_geo_info(src_ip)
        else:
            self.geo_info = geo_info

        if is_tor_relay is None:
            self.check_ip_for_tor_exit(src_ip)
        else:
            self.is_tor_relay = is_tor_relay

        # These don't exist for this type of token
        self.referer = referer
        self.location = location

        #  Again taken from email
        self.useragent = useragent


    def check_ip_for_tor_exit(self, ip):
        """Looks up whether the ip of this
        TokenHit is currently a tor exit node,
        and sets the local variable correspondingly"""
        if len(TokenHitEnrichmentClass.tor_node_list) == 0:
            # Initialize tor node list
            logging.info("Getting list of tor nodes from %s",
                    TokenHitEnrichmentClass.url_of_tor_node_list)
            response= requests.get(TokenHitEnrichmentClass.url_of_tor_node_list)
            TokenHitEnrichmentClass.tor_node_list = response.text.split("\n")
        TokenHitEnrichmentClass.tor_node_list.sort()

        self.is_tor_relay = ip in TokenHitEnrichmentClass.tor_node_list

    def get_geo_info(self, ip):
        """Looks up geo info for the ip of this
        TokenHit and sets the local variable correspondingly"""
        logging.info(f"Getting geo info for {ip}")
        json_response = requests.get(TokenHitEnrichmentClass.url_of_ipinfo.format(
            ip=ip, token=TokenHitEnrichmentClass.ipinfo_api_key))
        self.geo_info = json_response.text.replace("\n","")

    def to_csv_array(self):
        """Returns data of this TokenHit as an array, ready to be written to
        a .csv file"""
        return [self.timestamp.strftime("%Y-%m-%d %H:%M:%S (UTC)"),
                self.src_ip, self.input_channel, self.geo_info,
                self.is_tor_relay, self.referer, self.location, self.useragent]



def create_list_from_csv(filename):
    """Takes a csv file and returns a list
    of all tokenhits contained within that csv file.
    Naive, expects an exact match to the format we produce,
    including ordering of keys"""
    list_of_tokenhits = []
    with open(filename, mode ='r') as csv_file:
        reader = csv.reader(csv_file)
        next(reader) # Skip header line

        for line in reader:
            token_hit = TokenHit(
                    timestamp=line[0], src_ip=line[1], input_channel=line[3],
                    useragent=line[7],
                    geo_info=line[3], is_tor_relay=line[4],
                    referer=line[5], location=line[6])
            list_of_tokenhits.append(token_hit)
    return list_of_tokenhits


def build_token_hit_from_email(email):
    """Expects an opened file as input. Should be a .eml file
    that is formatted as emails sent by thinkst canary are formatted.
    Returns a (token_reminder,TokenHit) with the data from that email.
    Returns (None,None) if this email is not from canarytoken
    """
    # Startstring of html in email


    try:
        html_identifier = "w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
        email_string = email.read()
        html = email_string.split(html_identifier)[1]
        soup = BeautifulSoup(quopri.decodestring(html), features="lxml")

        # Classify emails based on TokenReminder
        token_reminder = soup.find("td", string="Token Reminder").find_next_sibling("td").get_text()
        if token_reminder is None:
            # Not an canary email
            return (None, None)
    except IndexError:
        return (None, None)
    except AttributeError:
        return (None, None)

    # Email appears to be compressed- class names are not consistent between emails
    channel = soup.find("td", string="Channel").find_next_sibling("td").get_text()
    timestamp = soup.find("td", string="Time").find_next_sibling("td").get_text()
    src_ip = soup.find("td", string="Source IP").find_next_sibling("td").get_text()
    user_agent = soup.find("td", string="User Agent").find_next_sibling("td").get_text()


    # In some cases the src_ip field contains two ip addresses - from our data
    # It appears that the first IP is local, and the second one lookup-able
    # This tries to get rid of this edgecase
    try:
        ip_address = ipaddress.ip_address(src_ip)
    except ValueError:
        # Is likely in the form ip1, ip2
        second_address = src_ip.split(", ")[1]
        ip_address = second_address

    tokenhit_from_email = TokenHit(timestamp, ip_address, channel, user_agent)
    return (token_reminder, tokenhit_from_email)


def write_token_hits_to_csv(csv_filename, list_of_token_hits):
    """Creates a csv that contains all tokenhits
    passed into this method."""
    with open(csv_filename, 'w') as csv_file:
        writer = csv.writer(csv_file, quoting=csv.QUOTE_ALL)

        writer.writerow(TokenHit.csv_header)

        for hit in list_of_token_hits:
            writer.writerow(hit.to_csv_array())
    return csv_filename


def get_name_if_should_not_query(email, base_path_to_output_csv, force):
    """For a given email, checks if a csv belonging to this tag already exists.
    Takes into account the current prefix (e.g. we only care for csv files with
    this prefix), and whetehr the user wants to force ignore existing csvs
    """
    if force is True:
        return None

    try:
        # Get token from email
        html_identifier = "w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
        email_string = email.read()
        html = email_string.split(html_identifier)[1]
        soup = BeautifulSoup(quopri.decodestring(html), features="lxml")
        # Classify emails based on TokenReminder
        token_reminder = soup.find("td", string="Token Reminder").find_next_sibling("td").get_text()
        if token_reminder is None:
            # Not an canary email
            return None
    except IndexError:
        return None
    except AttributeError:
        return None

    # Lookup if csv exists
    full_csv_filename = base_path_to_output_csv + token_reminder+ ".csv"
    if os.path.exists(full_csv_filename):
        return full_csv_filename
    return None


def add_token_if_is_valid(email, all_token_hits, base_path_to_output_csv):
    """Reads details from the token contained within
    the given email to the given all_token_hits list,
    if it belongs there"""
    token_reminder, token = build_token_hit_from_email(email)

    if token_reminder is None:
        return

    token_path = base_path_to_output_csv + token_reminder+ ".csv"
    if token_path not in all_token_hits:
        all_token_hits[token_path] = []

    all_token_hits[token_path].append(token)


def build_data_csvs(path_to_email_folder, base_path_to_output_csv, force=False):
    """Reads all files in the email folder, and writes
    all tokenhits into different csv files, depending on their
    "Token Reminder" string. base_path_to_output_csv is
    prepended to all csvs we create. Ignores entries
    if a csv with that reminder string (and prefix)
    already exists, this can be toggled with force"""
    # Iterate over all email files and create token hits
    all_token_hits = {}
    uncreated_csv_filenames = Counter()

    for email_file in os.scandir(path_to_email_folder):
        with open(email_file.path) as email:
            already_existing_file = get_name_if_should_not_query(email,
                    base_path_to_output_csv, force)

            if already_existing_file is not None:
                logging.info(f"Identified file {already_existing_file} as existing, blocking edit")
                # Don't overwrite/query these.
                # Decide this early to limit potentially expensive API lookups
                # Also prepare to print out list of these files
                uncreated_csv_filenames[already_existing_file] += 1
                continue
            # Reset stream to beginning, since we already
            # read it above
            email.seek(0, 0)
            add_token_if_is_valid(email, all_token_hits, base_path_to_output_csv)

    created_csv_filenames = []
    for path_to_output_csv, hits_at_path in all_token_hits.items():
        created_csv_filenames.append(
                write_token_hits_to_csv(path_to_output_csv, hits_at_path))
    return created_csv_filenames, uncreated_csv_filenames


def print_uncreated_file_details(uncreated_filenames):
    """Prints output giving user additional context
    if we did not create a specific csv for a reason"""
    if len(uncreated_filenames) == 0:
        return

    print("Warning: The following files already exist, and will not be modified, "\
            "even though the email folder contains token hits for them:")
    for filename, hits in uncreated_filenames.items():
        print(f"{filename} ({hits} token hits)")
    print("To overwrite these files call again with the --force option")

def print_created_file_details(created_filenames, no_visualize):
    """Prints output giving user additional context
    over created csv files"""
    if len(created_filenames) == 0:
        print("No csvs created")
        return

    print("Created these csvs:")
    for filename in created_filenames:
        print(filename)
    if no_visualize:
        print("Skipping visualization")

def create_csvs(input_folder, output_prefix, force):
    created_filenames, uncreated_filenames = build_data_csvs(args.input_folder,
            args.prefix, args.force)
    print_uncreated_file_details(uncreated_filenames)
    print_created_file_details(created_filenames, args.no_visualize)
    return created_filenames, uncreated_filenames





def main():
    """Reads all files in the given folder,
    creates a .csv out of them, then runs
    analysis + visualizations


    Example calls:
    python main.py --input_folder /folder --no-visualize
    Create csvs for all reminders in a folder that don't exist yet

    python main.py --input_files a.csv b.csv
    Visualise the given csv files

    python main.py --input_folder /folder --prefix "token_" --force
    Create csvs for all reminders in a folder in csv files that have a _token prefix,
    then display visualizations for these

    python main.py --input_folder /folder --input_files webpage.csv
    Create csvs for all reminders in a folder that don't exist yet,
    afterwards only display graphs for webpage.csv
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-if', '--input_folder', help='Path to a folder of .eml files')
    parser.add_argument('-ic', '--input_csvs', action='append', type=str,
            help='List of .csv that should be drawn. '\
            'If --input_folder is set this defaults to all files that would be created')

    parser.add_argument('-p', '--prefix', default="",
            help='Prefix for the csvs that are created by the email parsing step')

    parser.add_argument('-nv', '--no_visualize', action='store_true',
            help='Skip the visualization step. Overrides --input_csvs')
    parser.add_argument('-f', '--force', action='store_true',
            help='Overwrite existing .csvs, even if they already exist')

    args = parser.parse_args()
    if not (args.input_folder or args.input_csvs):
        parser.error("No action requested, please use --input_folder or --input_csvs")

    created_filenames = []
    # Do the csv creation step
    if args.input_folder is not None:
        created_filenames, uncreated_filenames = create_csvs()
    else:
        created_filenames = []
        uncreated_filenames = Counter()

    if args.no_visualize:
        return

    # Do the visualization step
    if args.input_csvs is not None:
        # Only draw files user explicitly selected - or default to all
        created_filenames = args.input_csvs


    list_of_tokenToGraph = []
    # Create list of TokenToDraw that is then passed to visualization
    for csv_filename in created_filenames + list(uncreated_filenames.keys()):
        list_of_all_tokenhits = create_list_from_csv(csv_filename)
        token_to_graph = analysis.TokenToGraph(csv_filename, list_of_all_tokenhits)
        list_of_tokenToGraph.append(token_to_graph)

    analysis.run_analyses(list_of_tokenToGraph)


if __name__ == "__main__":
    main()
