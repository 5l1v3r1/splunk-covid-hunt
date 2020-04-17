## TO-DO
#   1. Add config file for arguments (esp. slackbot details)

import yaml
import os.path
import argparse
import requests
from time import sleep
import urllib.parse
from urllib.parse import parse_qs
import xml.etree.ElementTree as ET
import pyperclip
try:
    from selenium import webdriver
    from selenium.common.exceptions import NoSuchElementException
    from selenium.webdriver.common.keys import Keys
except ImportError:
    raise ImportError('[WARNING] Selenium does not appear to be installed. Selenium is required to use the \'--no-api\' option.')

def main():
    # Initialize search option variables and read config file
    config_vetted = config_unvetted = config_ioc = splunk_addr = config_port = config_username = config_password = slack_webhook = config_outfile = config_noapi = config_numterms = config_earliest = config_latest = None
    if os.path.isfile("config.yml"):
        with open("config.yml", "r") as config:
            cfg = yaml.load(config, Loader=yaml.FullLoader)
        for var in cfg:
            if var == "vetted":
                config_vetted = cfg[var]
            elif var == "unvetted":
                config_unvetted = cfg[var]
            elif var == "ioc":
                config_ioc = cfg[var]
            elif var == "splunk_addr":
                splunk_addr = cfg[var]
            elif var == "port":
                config_port = cfg[var]
            elif var == "username":
                config_username = cfg[var]
            elif var == "password":
                config_password = cfg[var]
            elif var == "slackbot_webhook":
                slack_webhook = cfg[var]
            elif var == "outfile":
                config_outfile = cfg[var]
            elif var == "noapi":
                config_noapi = cfg[var]
            elif var == "num_terms":
                config_numterms = cfg[var]
            elif var == "time_earliest":
                config_earliest = cfg[var]
            elif var == "time_latest":
                config_latest = cfg[var]

    # Handle defaults for argparse
    if not config_vetted and not config_unvetted:
        config_vetted = config_unvetted = False
    if not config_ioc:
        config_ioc = 'all'
    if not config_numterms:
        config_numterms = 500
    if not config_earliest:
        config_earliest = '1'
    if not config_latest:
        config_latest = "now"
    if config_outfile:
        config_noapi = False

    # Create parser to collect and validate search options, if provided by command line
    parser = argparse.ArgumentParser(description='Query Splunk for COVID-19-related IOCs as listed by CyberThreatCoalition.org')
    group = parser.add_mutually_exclusive_group()
    group2 = parser.add_mutually_exclusive_group()
    group.add_argument('-v', '--vetted', dest='vetted', help="Include only vetted IOCs.", default=config_vetted, action="store_true")
    group.add_argument('-u', '--unvetted', dest='unvetted', help="Include only unvetted IOCs.", default=config_unvetted, action="store_true")
    parser.add_argument('--ioc', dest='ioc', help="Select IOCs to search for. Options: [ip, url, domain, hash, all]. Default = all.", choices=['ip', 'url', 'domain', 'hash', 'all'], default=config_ioc, nargs='+')
    if not splunk_addr:
        parser.add_argument('splunk_addr', help="URL of your Splunk instance.", type=str)
    parser.add_argument('-p', '--port', dest='port', help="Custom port for API calls. Default is 8089 or 8000 with --no-api flag.", default=config_port, type=str)
    parser.add_argument('--terms', dest="terms", help="Number of iocs to search for at a time. Default = 500.", default=config_numterms, type=max_terms)
    group2.add_argument('-o', '--outfile', '--output', dest='outfile', help="Path to output file. If no file is specified, search results will not be streamed and search SID will be returned.", default=config_outfile, type=str)
    parser.add_argument('--user', dest='username', help="Splunk username.", default=config_username, type=str)
    parser.add_argument('--pass', dest='password', help="Splunk pasword.", default=config_password, type=str)
    parser.add_argument('--earliest', dest='earliest', help='Splunk date code for earliest event to search: [%%m/%%d/%%Y:%%H:%%M:%%S] or -6h (relative)', default=config_earliest, type=str)
    parser.add_argument('--latest', dest='latest', help='Splunk date code for latest event to search: [%%m/%%d/%%Y:%%H:%%M:%%S] or -30m (relative)', default=config_latest, type=str)

    group2.add_argument('--no-api', dest='noapi', help='Leverage Selenium to perform search through browser without the need for API access. This option is not compatible with --outfile.', default=config_noapi, action='store_true')
    # Default set to chromedriver in same folder. Find a better way to do this and test what happens with mismatched drivers.
    #parser.add_argument('--webdriver', dest='webdriver', help='Filepath to webdriver for Selenium', default='chromedriver', nargs=1, type=str)

    args = parser.parse_args()
    
    # Set splunk_addr to accommodate config or CLI input
    if not splunk_addr:
        splunk_addr = args.splunk_addr

    # Require credentials
    if not args.username or not args.password:
        print("Missing Splunk credentials. Please use the -u|--username and -p|--password options or update your config.yml file.")
        return

    # Analyze arguments to summarize search selections for user
    if args.vetted:
        vetted_choice="[VETTED]"
    elif args.unvetted:
        vetted_choice="[UNVETTED]"
    else:
        vetted_choice="all [VETTED and UNVETTED]"

    if 'all' in args.ioc:
        ioc_choice = "['IP', 'URL', 'DOMAIN', 'HASH']"
        args.ioc = ['ip', 'url', 'domain', 'hash']
    else:
        ioc_choice = []
        for s in args.ioc:
            ioc_choice.append(s.upper())
    
    if args.outfile:
        args.noapi = False
    
    if args.noapi and args.port == None:
        args.port = "8000"
    elif not args.noapi and args.port == None:
        args.port = "8089"

    if args.outfile:
        result_dest="Results will be stored in [" + args.outfile.upper() + "]"
    else:
        result_dest="Search ID will be returned after search is started in Splunk"

    print('Querying Splunk at [' + str( splunk_addr.upper()) + '] on [PORT ' + str(args.port) + '] for ' + str(vetted_choice) + ' IOCs under ' + str(ioc_choice) + '. ' + str(result_dest) + '.\n\n')
    confirm = input("Is this correct? Continue [y/n]: ")

    # Accommodate inclusion/exclusion of web port in splunk address
    count = splunk_addr.count(':')
    if count == 2:
        baseurl =  splunk_addr.rsplit(':', 1)[0] + ":" + args.port
    else:
        baseurl = splunk_addr + ":" + args.port
    
    # Confirm search options with user input and search
    if confirm == 'y':
        # Fetch IOCs from cyberthreatcoalition blocklist
        ioc_array = fetch_iocs(args.vetted, args.unvetted, args.ioc)
        
        # Exit if no IOCs to search
        if not ioc_array:
            print("No matching IOCs found. Exiting...")
            return
        
        # Selenium search
        if args.noapi:
            browser = webdriver.Chrome()
            #browser = webdriver.Firefox()
            #browser = webdriver.Safari()
            login = selenium_login(args.username, args.password, baseurl, browser)
            if login == 0:
                sids = selenium_search(baseurl, browser, ioc_array, args.terms, args.earliest, args.latest)
                if not sids:
                    print("Error: No SIDs returned.")
                else:
                    # Attempt Slack notification
                    if slack_webhook:
                        print("Sending Slack notification(s)...")
                        for sid in sids:
                            slack_bot_webhook(slack_webhook, splunk_addr, None, sid)
                    else:
                        print("No Slack webhook. Printing SIDs...")
                    # Print results to terminal
                    for sid in sids:
                        print("Search completed! Your results can be found at " + str(splunk_addr) + "/app/search/search?sid=" + str(sid))     
            else:
                print("Login failed! Exiting...")
            browser.close()
            browser.quit()
        
        # API search
        else:
            sids = search(args.username, args.password, baseurl, args.outfile, ioc_array, args.terms, args.earliest, args.latest)
        
        # Check for results
        if args.outfile:
            print("Your results have been printed to a local file: " + args.outfile)
        elif not sids:
            print("API request did not return expected xml response. Exiting...")
        else:
            # Attempt Slack notification
            if slack_webhook:
                print("Sending Slack notification(s)...")
                for sid in sids:
                    slack_bot_webhook(slack_webhook, splunk_addr, None, sid)
            else:
                print("No Slack webhook. Printing SIDs...")
            # Print results to terminal
            for sid in sids:
                print("Search completed! Your results can be found at " + str(splunk_addr) + "/app/search/search?sid=" + str(sid))
    else:
        print("Exiting...")

# Validate num_terms option input
def max_terms(value):
    val = int(value)
    if val <= 0 or val > 3000:
        raise argparse.ArgumentTypeError("Invalid number of terms: " + str(value) + ". --terms must be between 1 and 3000 (inclusive).")
    return val

# Fetches specified IOCs from CyberThreatCoalition blocklist and returns search terms as array
def fetch_iocs(vetted, unvetted, ioc_sel):
    files = []
    for ioc in ioc_sel:
        files.append(ioc + ".txt")
    
    if vetted:
        for i,f in enumerate(files):
            files[i] = "https://blocklist.cyberthreatcoalition.org/vetted/" + f
    elif unvetted:
        for i,f in enumerate(files):
            files[i] = "https://blocklist.cyberthreatcoalition.org/unvetted/" + f
    else:
        files_copy = files.copy()
        for i,f in enumerate(files):
            files[i] = "https://blocklist.cyberthreatcoalition.org/vetted/" + f
        for i in range(0, len(files_copy)):
            files.append("https://blocklist.cyberthreatcoalition.org/unvetted/" + files_copy[i])

    ioc_str = ''
    ioc_array = []
    for i,f in enumerate(files):
        print("\n" + f)
        if "/vetted" in f:
            if "ip.txt" in f:
                print("\nFetching vetted IPs...\n")
            elif "url.txt" in f:
                print("\nFetching vetted URLs...\n")
            elif "domain.txt" in f:
                print("\nFetching vetted domains...\n")
            elif "hash.txt" in f:
                print("\nFetching vetted filehashes...\n")
        elif "/unvetted" in f:
            if "ip.txt" in f:
                print("\nFetching unvetted IPs...\n")
            elif "url.txt" in f:
                print("\nFetching unvetted URLs...\n")
            elif "domain.txt" in f:
                print("\nFetching unvetted domains...\n")
            elif "hash.txt" in f:
                print("\nFetching unvetted filehashes...\n")

        r = requests.get(f, verify=True)
        tmp = r.text.split('\r\n',1)[1]
        tmp = tmp.rsplit('\r\n',1)[0]
        ioc_str += tmp.replace('\r\n', ' ')
    
    ioc_str = match_brackets(ioc_str)
    # FOR DEBUGGING
    # with open('iocs.txt', 'w+') as f:
    #     f.write(ioc_str)
    if ioc_str == '':
        return
    else:
        ioc_str = ioc_str.replace('\\', '\\\\')
        ioc_array = ioc_str.replace('"', '').split(' ')
        return ioc_array

# Remove lonely brackets found in the data set
def match_brackets(query):
    pairs = {"[": "]"}
    stack = []
    mismatched = []
    i=0
    for c in query:
        if c in "[":
            stack.append(c)
        elif stack and c == pairs[stack[-1]]:
            stack.pop()
        elif c in "]":
            mismatched.append(i)
        i += 1
    if mismatched:
        result = query[:mismatched[0]]
        for i in range(0,len(mismatched)-1):
            result += query[mismatched[i]+1:mismatched[i+1]]
        result += query[mismatched[-1]+1:]
    else:
        result = query
    return result
        

# Sends search query to Splunk API
def search(username, password, baseurl, outfile, ioc_array, num_terms, earliest, latest):
    # Set search endpoint
    endpoint = baseurl + "/services/search/jobs"
    if outfile:
        endpoint += "/export"
    
    # Construct query(ies)
    search_terms = []
    search_term = 'search earliest=' + earliest + ' latest=' + latest + ' "'
    i = 0
    for t in range(0, len(ioc_array)-1):
        search_term += ioc_array[t] + '" OR "'
        i += 1
        if i == num_terms:
            search_terms.append(search_term[:-5])
            search_term = 'search earliest=' + earliest + ' latest=' + latest + ' "'
            i = 0
    if i != 0:
        search_terms.append(search_term[:-5])
    # FOR DEBUGGING
    #search_terms = ["search earliest=" + earliest + " latest=" + latest + " VendorID=5036 OR VendorID=1074 OR VendorID=1075 OR VendorID=1076"]
    
    # Send query(ies)
    print("Querying " + endpoint)
    #requests.packages.urllib3.disable_warnings()
    results = []
    i = 0
    for t in search_terms:
        print("Queries sent: ", i)
        payload = {"search":t}
        r = requests.post(endpoint, auth=(username, password), data=payload, verify=False)
        results.append(r)
        i += 1

    # Parse XML response and write to outfile
    sids = []
    if outfile:
        f = open(outfile, "w+")
        for result in results:
            parsexml(result.text, f)
        f.close()
        return
    # Parse XML responses and return array of SIDs
    else:
        for result in results:
            sids.append(parsexml(result.text))
        return sids

# Login to Splunk via web portal using Selenium
def selenium_login(username, password, baseurl, driver):
    login_url = baseurl + "/account/login"
    driver.get(login_url)
    sleep(5)
    username_field = driver.find_element_by_id('username')
    password_field = driver.find_element_by_id('password')
    submit_button = driver.find_element_by_class_name('btn-primary')
    username_field.send_keys(username)
    password_field.send_keys(password)
    submit_button.click()
    sleep(5)
    try:
        logged_in = driver.find_element_by_xpath('//*[@title="User"]')
        return 0
    except NoSuchElementException as e:
        print("Splunk login failed!\nExiting...")
        return 1

# Perform search using Selenium and return array of SIDs
def selenium_search(baseurl, driver, ioc_array, num_terms, earliest, latest):
    # Set search endpoint
    endpoint = baseurl + "/app/search/search"

    # Construct query(ies)
    sids = []
    search_terms = []
    search_term = 'search earliest=' + earliest + ' latest=' + latest + ' "'
    i = 0
    for t in range(0, len(ioc_array)-1):
        search_term += ioc_array[t] + '" OR "'
        i += 1
        if i == num_terms:
            search_terms.append(search_term[:-5])
            search_term = 'search earliest=' + earliest + ' latest=' + latest + ' "'
            i = 0
    if i != 0:
        search_terms.append(search_term[:-5])
    #search_terms = ["VendorID=5036 earliest=0","VendorID=1043 earliest=0"]

    # Send query(ies) and return array of SIDs
    for t in search_terms:
        driver.get(endpoint)
        sleep(5)
        search_bar = driver.find_element_by_class_name('ace_text-input')
        pyperclip.copy(t)
        search_bar.send_keys(Keys.CONTROL, 'v')
        search_button = driver.find_element_by_xpath('//td[@class="search-button"]//a[@class="btn"]')
        search_button.click()
        sleep(10)
        parsed = urllib.parse.urlparse(driver.current_url)
        sids.append(str(parse_qs(parsed.query)['sid'])[2:-2])
    return sids

def parsexml(xml_response, outfile=None):
    # Instantiate tree from string
    root = ET.fromstring(xml_response)

    try:
        if not outfile:
            return root[0].text
        else:
            # Check if message type is FATAL (empty search) 
            if (root[0][0].tag == "msg") and "Empty search" in root[0][0].text:
                print("Query returned 0 results.", file=outfile)
                return 1

            # Get number of results
            numResults = 0
            for child in root:
                if (child.tag == "result"):
                    numResults += 1
            print("Query returned " + str(numResults) + " results.", file=outfile)
            print("Query returned ", numResults, " results.")

            for resultIndex in range(0, numResults):
                print("\n\nRESULT (#)  |   FIELD (#)   |   FIELD NAME   |   VALUE", file=outfile)
                print(resultIndex+1, file=outfile)
                print("------------------------------------------------------------", file=outfile)
                # find number of fields for that result
                numberOfFieldsForCurrentResult = len(list(root[resultIndex+2]))
                for fieldIndex in range(0, numberOfFieldsForCurrentResult):
                    if (root[resultIndex+2][fieldIndex][0].tag == "value"):
                        # check if there is more than 1 value tag
                        numberOfValueTags = len(list(root[resultIndex+2][fieldIndex]))
                        if (numberOfValueTags == 1):
                            print("\t\t", fieldIndex+1, "\t", root[resultIndex+2][fieldIndex].attrib['k'], "\t", root[resultIndex+2][fieldIndex][0][0].text, file=outfile)
                        else:
                            for valueIndex in range (0, numberOfValueTags):
                                print("\t\t", fieldIndex+1, "\t", root[resultIndex+2][fieldIndex].attrib['k'], "\t", root[resultIndex+2][fieldIndex][valueIndex][0].text, file=outfile)
                    # check if there is a tag not named 'value' and print it
                    else:
                        print("\t\t", fieldIndex+1, "\t", root[resultIndex+2][fieldIndex].attrib['k'], "\t", root[resultIndex+2][fieldIndex][0].text, file=outfile)
            return numResults
    except:
        print("An exception occured while attempting to parse")

def slack_bot_webhook(webhook, baseurl, num_results=None, job_sid=''):
    # TO-DO - Still missing result count (parsexml return)
    if not job_sid:
        job_sid = "Your results were exported to a local file."
    else:
        job_sid = "Your results can be found at " + str(baseurl) + "/app/search/search?sid=" + str(job_sid)
    if num_results:
        num_results = " with " + str(num_results) + " results."
    else:
        num_results = "."
    message="Your Splunk query for COVID-19 related IOCs has completed" + str(num_results) + "\n\n" + str(job_sid)
    payload={"text":message}
    try:
        r = requests.post(webhook, json=payload)
    except requests.exceptions.RequestException as e:
        print("Error contacting Slack Bot via supplied webhook:")
        print(e)
    return
    
if __name__ == '__main__':
    main()
