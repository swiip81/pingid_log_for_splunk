#!/usr/bin/env python
__author__ = "fusseil"
__license__ = "GPL"
import requests
import json
import argparse
import configparser
import time
import os
from datetime import datetime, timedelta

help_desc = '''
Perform CS hosts details queries in order to produce a file for a splunk input

Config file must be filled with a stanza specified as --account %PUT_A_NAME_HERE%
[%PUT_A_NAME_HERE%]
pingid_oauth2_cid = %YOUR_CID_HERE%
pingid_oauth2_key = %YOUR_KEY_HERE%
pingid_report = %YOUR_KEY_HERE%
pingid_output_filename = %YOUR_OUT_FILENAME_HERE%
'''


# import logging
def enable_http_debug():
    """JUST TO GET MORE HTTP DEBUG call me somewhere"""
    try:
        import http.client as http_client
    except ImportError:
        import http.client as http_client
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def pingid_init_config(account):
    """Read configuration file to get oauth2 cedentials"""
    config = configparser.RawConfigParser()
    try:
        config.read(config_file)
        pingid_oauth2_cid = str(config.get(account, 'pingid_oauth2_cid'))
        pingid_oauth2_key = str(config.get(account, 'pingid_oauth2_key'))
        pingid_report = str(config.get(account, 'pingid_report'))
        pingid_output_filename = str(config.get(account, 'pingid_output_filename'))
    except Exception as e:
        print("Check your config file {0} for section [{1}] and rerun the program, exiting...".format(config_file, account))
        exit(1)
    return (pingid_oauth2_cid, pingid_oauth2_key, pingid_report, pingid_output_filename)


def pingid_request(method, url, headers=None, params=None, data=None, json_data=None):
    """Method to handle resquests to pingId APIs"""
    pingid_tempo = 0.02
    response, return_value = None, None
    json_header = {"Content-Type": "application/json"}
    headers = json_header if headers is None else headers
    SUPPORTED_METHODS = ['GET', 'POST']
    if method not in SUPPORTED_METHODS:
        print("{0} method is not a supported".format(method))
        exit(1)
    try:
        if args.debug:
            print("API Request. method: {0} url: {1}".format(method, url))
            print("             headers: {0} data: {1} params: {2}".format(headers, data, params))
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params)
        elif method == 'POST':
            response = requests.post(url, headers=headers, params=params, data=data, json=json_data)
        response.raise_for_status()
        return_value = response.json()
        if args.debug: print("Request successful")
    except requests.exceptions.Timeout:
        print("API request timed out")
        exit(1)
    except requests.exceptions.TooManyRedirects:
        print("API Too Many Redirects")
        exit(1)
    except requests.exceptions.RequestException as err:
        print(err)
        exit(1)
    except requests.exceptions.HTTPError as err:
        if err.response.content:
            response_content = response.json()
            response_errors = response_content.get('errors')
            response_error_code = response_errors[0].get('code')
            if response_errors and len(response_errors) > 0 and response_error_code in (403, 409, 404):
                print("err_code: {0} err_msg: {1}".format(response_error_code, response_errors[0].get('message')))
                exit(1)
        raise ValueError(err)
    # Tempo to protect from a max api rate limit
    time.sleep(pingid_tempo)
    return return_value


def get_oauth2_token():
    """Calls oauth2 token endpoint and sets the new token"""
    get_oauth2_token_url = "{0}{1}".format(pingid_oauth2_base_url, "/latest/as/token.oauth2")
    get_oauth2_headers = {"accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    get_oauth2_token_data = "client_id={0}&client_secret={1}&grant_type=client_credentials&scope=edit".format(pingid_oauth2_cid, pingid_oauth2_key)
    if args.debug: print("Requesting new oauth2 Token from {0}".format(get_oauth2_token_url))
    get_oauth2_token_response = pingid_request(
        method='POST',
        url=get_oauth2_token_url,
        data=get_oauth2_token_data,
        headers=get_oauth2_headers)
    if get_oauth2_token_response.get('error'):
        print("Error getting new oauth2 Token from CrowdStrike: {0}".format(get_oauth2_token_response.get("err_msg")))
        exit(1)
    oauth2_token = get_oauth2_token_response.get("access_token")
    if args.debug: print("New oauth2 Token set successfully {0}".format(get_oauth2_token_response))
    return oauth2_token

def get_pingid_logs(output_file):
    get_all_logs_header = {"Content-Type": "application/json", "authorization": "bearer {0}".format(oauth2_token)}
    get_all_logs_url = "{0}/v3/reports/{1}".format(pingid_oauth2_base_url, pingid_report)
    get_all_logs_response = pingid_request(
            method='GET',
            url=get_all_logs_url,
            headers=get_all_logs_header)
    if args.debug: print("Result {0}".format(get_all_logs_response))
    count=0
    for resource_details in get_all_logs_response:
        count+=1
        if resource_details is not None:
            if args.debug: print(json.dumps(resource_details))
            # we try to avoid "source" field in the upstream...
            resource_details["pingid_source"]=resource_details["source"]
            del resource_details["source"]
            json.dump(resource_details, output_file)
            output_file.write('\n')
    return count

if __name__ == '__main__':
    pingid_oauth2_base_url = 'https://admin-api.pingone.com'
    time_str = time.strftime("_%Y%m%d%H%M%S")
    config_file = '/opt/splunk/.config/pingid.cfg'
    #config_file = "./pingid.cfg"
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c', '--config_file', type=str, help="Specify alt config file")
    parser.add_argument('-a', '--account', type=str, help="Account to use aka config stenza", required=True)
    parser.add_argument('-d', '--debug', action='store_true', help="Enable debugging mode. Default: disabled.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose mode. Default: disabled.")
    args = parser.parse_args()

    if args.config_file: config_file = args.config_file
    (pingid_oauth2_cid, pingid_oauth2_key, pingid_report, pingid_output_filename) = pingid_init_config(args.account)
    oauth2_token = get_oauth2_token()
    # make sure the target directory exists
    if not os.path.exists(pingid_output_filename): os.makedirs(pingid_output_filename)
    pingid_output_filename=pingid_output_filename+args.account
    if not os.path.exists(pingid_output_filename): os.makedirs(pingid_output_filename)
    #os.makedirs(os.path.dirname(pingid_output_filename), exist_ok=True)
    with open(pingid_output_filename+"/"+args.account+time_str+".tmp", 'w') as output_file:
        count=get_pingid_logs(output_file)
    print("New elements found for {0} at {1} : {2}".format(args.account ,time_str, count))
    # if the result is an emty file, we delete it, or we rename it to make it visible to splunk
    if os.stat(pingid_output_filename+"/"+args.account+time_str+".tmp").st_size == 0:
        os.remove(pingid_output_filename+"/"+args.account+time_str+".tmp")
    else:
        os.rename(pingid_output_filename+"/"+args.account+time_str+".tmp",
                  pingid_output_filename+"/"+args.account+time_str+".log")
    # if we found less than 20 events with exit with succes, or 
    # we exit with 20 to inform the wrapper that a new imediate run is needed
    if count < 20:
        exit(0)
    else:
        exit(20)
