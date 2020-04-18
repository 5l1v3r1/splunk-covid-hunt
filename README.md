# Splunk-COVID-Hunt
A Python script to query Splunk for COVID-19 related IOCs as listed by CyberThreatCoalition.org.

## Dependencies
- Python 3.x
- PyYAML `pip install pyyaml`
- ElementPath `pip install elementpath`
- Selenium (optional, if no Splunk API access) `pip install selenium`
  - ChromeDriver WebDriver for your version of Chrome - https://chromedriver.chromium.org/downloads
  - Pyperclip `pip install pyperclip`

## Setup and Usage
1. Ensure all listed dependencies are installed
    1. If you intend to use Selenium to search without using Splunk's REST API, all items under Selenium must be installed. Otherwise, they are optional.
1. Place chromedriver.exe in the same directory as splunk-covid-hunt.py and config.yml.
1. Populate config.yml with the information of your Splunk instance and your desired search options.
```powershell 
python ./splunk-covid-hunt.py [-h] [-v | -u] [--ioc {ip,url,domain,hash,all} [{ip,url,domain,hash,all} ...]] [-p PORT] [--terms TERMS] [-o OUTFILE] [--user USERNAME] [--pass PASSWORD] [--earliest EARLIEST] [--latest LATEST] [--no-api]
```

## Description
This script fetches indicators of compromise related to the COVID-19 pandemic as reported by CyberThreatCoalition.org (See the blocklist at https://www.cyberthreatcoalition.org/). These IOCs are IPs, URLs, Domains, and Filehashes that have either been human-vetted and confirmed or remain unvetted and potentially related. Splunk-COVID-Hunt allows you to query your Splunk instance for some or all of these. 

If you have API access on your Splunk instance, you can have the search return the SID(s) of the search job(s) that were executed or stream the results to an output file. If you are not exporting to a file, you can configure a [Slack App](https://slack.com/intl/en-ca/help/articles/115005265063-Incoming-Webhooks-for-Slack) to provide a notification via webhook with links to your search job(s).

If you do not have API access, you can use the magic of Selenium's browser automation (by invoking the `--no-api` flag)! The script will access your splunk instance through your web browser and perform searches "manually" as a human normally would:

![](selenium_search2.gif)

This option is not compatible with exporting to file, but can still leverage a Slack App for notifications with result links.

## Config file options
Config settings will be pulled from `config.yml`. A skeleton config file can be found [here](https://github.com/secdevopsteam/splunk-covid-hunt/blob/master/config.yml).
Option | Description | Sample
------------|-----------------------------|------------
`splunk_addr`| `<str>` The URL of your splunk instance. If a port number is required for browser access it must be included. | `"https://splunk.companyxyz.com"`<br/>`"https://splunk.companyxyz.com:8000"`
`port` | `<str>` Splunk's API port. Default is `8089` | `"1234"`
`username` | `<str>` The username of the Splunk user that will perform the search. | `"drjonassalk"`
`password` | `<str>` The password of the Splunk user that will perform the search. | `"NoP@tentNoPoli0"`
`vetted` | `<bool>` Search only for IOCs that have been vetted by a human. If both `vetted` and `unvetted` are `False`, both will be searched. | `True`
`unvetted` | `<bool>` Search only for potential IOCs that have not yet been vetted. If both `vetted` and `unvetted` are `False`, both will be searched. | `True`
`ioc` | `<list><str>` List of IOC types to search for. Options: `-"ip"` `-"url"` `-"domain"` `-"hash"` `-"all"`. If `"all"` option is present, all IOCs will be fetched, regardless of other selections. Default is `"all"`.<br/><br/>Note that CyberThreatCoalition.org is constantly changing/updating their blocklist -- some of these options may not be populated. | See [config.yml](https://github.com/secdevopsteam/splunk-covid-hunt/blob/master/config.yml) for YAML syntax
`time_earliest` | `<str>` [Splunk time modifier](https://docs.splunk.com/Documentation/Splunk/8.0.3/SearchReference/SearchTimeModifiers) for earliest bound of search range. Default is `1` (UNIX Epoch) | `"@d"` `"-12h"` `"06/29/1996:19:07:12"`
`time_latest` | `<str>` [Splunk time modifier](https://docs.splunk.com/Documentation/Splunk/8.0.3/SearchReference/SearchTimeModifiers) for latest bound of search range. | `"now"` `"-6h"` `"11/02/2019:04:12:00"`
`num_terms` | `<int>` Number of IOCs to search for at a time (to prevent hitting buffer limit, especially when using browser with Selenium). Range is `1` to `3000`, inclusive. Default is `500` | `50` `1000` 
`outfile` | `<str>` Path to output file for result export. This overrides the `noapi` option and `--no-api` flag.<br/><br/>Note: if the file already exists, it will be overwritten without prompt. | `"/path/to/output.txt"`
`noapi` | `<bool>` Indicates use of Selenium via browser and Splunk web port over API-triggered search. Not compatible with `outfile` option or `--outfile` flag. Default is `False` | `True`
`slackbot_webhook` | `<str>` Webhook for the Slack App configured to post to a specific channel. Setup details can be found [here](https://slack.com/intl/en-ca/help/articles/115005265063-Incoming-Webhooks-for-Slack). | Details on Slack webhooks [here](https://api.slack.com/messaging/webhooks#posting_with_webhooks#posting_with_webhooks).

## Input argument options
All commandline arguments override `config.yml` options aside from `splunk_addr`, which will not be an available positional argument if `splunk_addr` is specified in the config file. More detailed option descriptions  and option defaults can be found in the [table above](#config-file-options).
Option | Description
------------|------------
`splunk_addr` | The URL of your splunk instance. If a port number is required for browser access it must be included. NOTE: Do not include if `splunk_addr` is already included in your `config.yml`
`--user`<br/>`--username` | Username
`--pass`<br/>`--password` | Password
`-v`<br/>`--vetted` | Search only for vetted IOCs
`-u`<br/>`--unvetted` | Search only for unvetted IOCs
`--ioc` | IOC type selection. Options are `ip` `url` `domain` `hash` or `all`. Default is `all`. Usage: `--ioc ip domain`.
`--earliest` | Search timerange earliest bound. Syntax follows [Splunk time modifier documentation](https://docs.splunk.com/Documentation/Splunk/8.0.3/SearchReference/SearchTimeModifiers)
`--latest` | Search timerange 'latest' bound. Syntax follows [Splunk time modifier documentation](https://docs.splunk.com/Documentation/Splunk/8.0.3/SearchReference/SearchTimeModifiers)
`--terms` | Number of IOCs per search query.
`-o`<br/>`--outfile` | Path of file to output results.
`--no-api` | Set to `True` to use Splunk web portal with Selenium browser automation instead of Splunk API.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## To-Do
1. Add count of results to Slack notification
    1. for searches using Selenium
    1. for non-export API searches
1. Add slack notification for completion of API searches using the `/export` endpoint
1. Add support for other SIEMs (e.g. ArcSight, QRadar, etc.)

## Contributors
Jordan O'Neill<br/>
Naeem Budhwani<br/>
Mohammad Faghani<br/>




