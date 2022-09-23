"""Parses a folder of emails sent by Thinkst canarytoken and creates a
.csv that corresponds to the csv that is directly downloadable from the token page
"""

import csv
import os
import argparse
import logging

import requests
from bs4 import BeautifulSoup

class TokenHitEnrichmentClass:
    """Convenience class to store data used for lookups that
    we need globally     and only want to initialize once"""
    tor_node_list = None
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
        self.timestamp = timestamp
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
        if TokenHitEnrichmentClass.tor_node_list is None:
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
        json_response = requests.get(TokenHitEnrichmentClass.url_of_ipinfo.format(
            ip=ip, token=TokenHitEnrichmentClass.ipinfo_api_key))
        self.geo_info = json_response.text

    def to_csv_array(self):
        """Returns data of this TokenHit as an array, ready to be written to
        a .csv file"""
        return [self.timestamp, self.src_ip, self.input_channel, self.geo_info,
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
    Returns a TokenHit with the data from that email.
    """
    # Startstring of html in email
    html_identifier = "w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
    email_string = email.read()
    html = email_string.split(html_identifier)[1]
    soup = BeautifulSoup(html, features="lxml")
    # Email appears to be compressed- class names are not consistent between emails

    channel = soup.find("td", string="Channel").find_next_sibling("td").get_text()
    timestamp = soup.find("td", string="Time").find_next_sibling("td").get_text()
    src_ip = soup.find("td", string="Source IP").find_next_sibling("td").get_text()
    user_agent = soup.find("td", string="User Agent").find_next_sibling("td").get_text()

    tokenhit_from_email = TokenHit(timestamp, src_ip, channel, user_agent)
    return tokenhit_from_email


def write_token_hits_to_csv(csv_filename, list_of_token_hits):
    """Creates a csv that contains all tokenhits
    passed into this method"""
    with open(csv_filename, 'w') as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(TokenHit.csv_header)

        for hit in list_of_token_hits:
            writer.writerow(hit.to_csv_array())


def build_data_csv(path_to_email_folder, path_to_output_csv):
    """Reads all files in the email folder, and writes
    their info to a csv file given as second argument."""
    # Iterate over all email files and create token hits
    all_token_hits = []
    for email_file in os.scandir(path_to_email_folder):
        with open(email_file.path) as email:
            all_token_hits.append(build_token_hit_from_email(email))

    write_token_hits_to_csv(path_to_output_csv, all_token_hits)





def main():
    """Reads all files in the given folder,
    creates a .csv out of them, then runs
    analysis + visualizations"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help="Path to a folder of .eml files")
    parser.add_argument('-co', '--csv_output', required = True,
            help="Path to where the output csv should be created/read from")
    parser.add_argument('-f', '--force', action='store_true',
            help="force script to run even if .csv already exists")
    args = parser.parse_args()
    # Check if .csv file already exists, pass in -f to overwrite

    if os.path.exists(args.csv_output) and not args.force:
        print("csv already exists. Use -f to overwrite")
        print("Using existing csv for data analysis...")
    else:
        if args.input is None:
            print("No --input folder given and no existing csv found")
            return
        build_data_csv(args.input, args.csv_output)


    list_of_all_tokenhits = create_list_from_csv(args.csv_output)

    # run_analyses(list_of_all_tokenhits)
    # TODO Check against click-throughs to platypus-facts, TLD


if __name__ == "__main__":
    main()
