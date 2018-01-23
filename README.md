# SecurityTrails Add-On for Splunk

## SecurityTrails Mission
SecurityTrails strives to make the biggest treasure-trove of cyber intelligence data readily available in an instant. We work relentlessly to empower experts so they can thwart future attacks with up-to-date data, proprietary tools, and custom solutions.

## Overview
This Add-On provides a method to use Splunk Adaptive Response to automate lookup of a Domain or IP against SecurityTrails API located [here](https://jsapi.apiary.io/apis/securitytrailsrestapi/reference/general.html).  Currently we support the following API calls.
- Get Domain Information
- List Subdomains
- List Tags
- WHOIS
- Historical DNS
- Historical WHOIS
- Domain Searcher (Searching Domains)
- IP Range Checker


## SecurityTrails Add-On For Splunk Requirements
This Add-On requires access to the SecurityTrails API located [here](https://securitytrails.com/splunkapp)

### Installation
1. Either git clone this directory 'git clone https://github.com/secops4thewin/TA-securitytrails.git' or download the spl file located here.
2. Install the add-on to the indexer and search head in your Splunk environment
3. On the Search Head open the add on by going to http://yoursplunkserver:8000/en-GB/app/TA-securitytrails/configuration
4. Enable a proxy if it is required
5. Click Add-on Settings and enter the API Key and the Index. 
6. Click Save
7. Create a search that produces a result such as a domain name and pass the results using the Splunk tokens such as $result.src_ip$ or $src_ip$


## Release Notes
1.0.0 Initial release with API functionality