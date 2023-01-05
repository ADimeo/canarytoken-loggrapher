# Canarytoken log analysis
Create graphs out of the .csv [Thinkst canarytoken](https://www.canarytokens.org/) provides, and create a .csv out canarytoken notifier emails if you want more history than what the downloadable .csv contains

Note: This software is very early stage, and currently not optimised for usage by non-authors. If you want to use it hit me up and I'll get it up to shape - I mean it!


## Usage
### From an existing .csv
Requires a .csv file in the format provided by the Canarytokens
1. Clone Repo with `git clone git@github.com:ADimeo/canarytoken-loggrapher.git` and `cd` into the project folder
2. Install dependencies [(ideally in some isolated environment)](https://www.dabapps.com/blog/introduction-to-pip-and-virtualenv-python/) `pip install --requirement requirements.txt`
3. Run with `python3 main.py -i path_to_logfile.csv`

Graphs will be shown one by one.

### Parsing emails
1. Clone Repo with `git clone git@github.com:ADimeo/canarytoken-loggrapher.git` and `cd` into the project folder
2. Install dependencies [(ideally in some isolated environment)](https://www.dabapps.com/blog/introduction-to-pip-and-virtualenv-python/) `pip install --requirement requirements.txt`
3. In `main.py` modify the `ipinfo_api_key` variable in the TokenHitEnrichmentClass to be an API key from [ipinfo.io](https://ipinfo.io/). Free tier is sufficient and signup is fast.
4. Create a a folder with all the emails you want to parse. For Thunderbird, "Save as" works very well. Make sure that only canarytoken emails are in the given folder, parsing is currently not robust.
5. Run with `python3 main.py -ei path/to/folder -i  path_to_logfile_to_create.csv`. Run with `-f` if you want to overwrite an already existing .csv

## Detailed Description
[canarytokens](https://www.canarytokens.org/) allow for the easy creation of a tracking pixel. This pixel can act as a poor mans logging function, if server logs can't be accessed and an analytics solution is not available. By default the publicly available canarytokens page only stores the last 50 hits, this can be circumvented by extracting additional data from the emails the canary sends on a hit.
This project helps analyzing those canary logs by generating a few simple graphs.

## Currently implemented graphs
- Requests over time
- Requests by country
- Requests by region
- Requests by browser family
- Requests by OS
- Requests from mobile devices vs non-mobile devices
