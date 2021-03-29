"""
This script will strip a HAR file to include only SAML request and response data,
and redact all cookie and header data.

Running from the command line, the first argument is the path to the source file, which
should contain at least one SAML Request and one SAML Response. The second argument is the output path
for the redacted files. The third argument is a template for the output filenames.
"""

import json
from datetime import datetime, timedelta
from copy import deepcopy
import sys
import os


def redact_har_file(source_file, destination_path, filename_template):
    # Read source file
    with open(source_file, 'r') as f:
        har = json.load(f)

    # Find only SAML Request and Response data in the HAR file
    entries = [e for e in har['log']['entries']
                     if e['request']['method'] == 'POST' and \
                     any(p['name'].startswith('SAML') for p in e['request'].get('postData', {}).get('params', []))]

    # Redact header and cookie values
    for entry in entries:
        for t in ('request', 'response'):
            for category in ('cookies', 'headers'):
                for values_to_edit in entry[t][category]:
                    values_to_edit['value'] = "redacted"

    # Collect pages that match the entries found
    page_nums = {p['pageref'] for p in entries}
    pages = [p for p in har['log']['pages'] if p['id'] in page_nums]

    # Create a second set of SAML data entries which are one day in the future.
    # This is to test having multiple entries in the file.
    second_response_entries = []

    for entry in entries:
        raw_timestamp = entry['startedDateTime']

        # HAR timestamps have a colon in the timezone offset. Removing it here.
        if ":" == raw_timestamp[-3:-2]:
            raw_timestamp = raw_timestamp[:-3] + raw_timestamp[-2:]
        timestamp = datetime.strptime(raw_timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        new_timestamp = timestamp + timedelta(days=1)

        new_raw_timestamp = new_timestamp.strftime("%Y-%m-%dT%H:%M:%S")
        # HAR timestamps have milliseconds instead of microseconds. Removing excess digits.
        new_raw_timestamp += new_timestamp.strftime(".%f")[:4]
        # HAR timestamps have a colon in the timezone offset. Adding it in here.
        new_raw_timestamp += new_timestamp.strftime("%z")
        new_raw_timestamp = new_raw_timestamp[:-2] + ":" + new_raw_timestamp[-2:]

        new_entry = deepcopy(entry)
        new_entry['startedDateTime'] = new_raw_timestamp
        second_response_entries.append(new_entry)

    responses = []
    requests = []

    for entry in entries + second_response_entries:
        if any(p['name'] == 'SAMLRequest' for p in entry['request']['postData']['params']):
            requests.append(entry)
        else:
            responses.append(entry)

    both_types_out = {'log': {
        'pages': pages,
        'entries': entries + second_response_entries}
    }

    responses_out = {'log': {
        'pages': pages,
        'entries': responses}
    }

    requests_out = {'log': {
        'pages': pages,
        'entries': requests}
    }

    no_saml_data_out = {'log': {
        'pages': pages,
        'entries': []}
    }

    with open(os.path.join(destination_path, filename_template + "_saml.har"), 'w') as f:
        json.dump(both_types_out, f)

    with open(os.path.join(destination_path, filename_template + "_requests.har"), 'w') as f:
        json.dump(requests_out, f)

    with open(os.path.join(destination_path, filename_template + "_responses.har"), 'w') as f:
        json.dump(responses_out, f)

    with open(os.path.join(destination_path, filename_template + "_nodata.har"), 'w') as f:
        json.dump(no_saml_data_out, f)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise ValueError("Incorrect number of arguments specified! "
                         "Need source file, destination path, filename template")
    redact_har_file(*sys.argv[1:])
