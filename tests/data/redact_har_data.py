"""
This script will strip a HAR file to include only SAML request and response data,
and redact all cookie and header data.

Running from the command line, the first argument is the path to the source file and
the second is the path to the destination.
"""

import json
from datetime import datetime, timedelta
from copy import deepcopy
import sys


def redact_har_file(source_file, destination_file):
    # Read source file
    with open(source_file, 'r') as f:
        har = json.load(f)

    # Find only SAML Request and Response data in the HAR file
    response_data = [e for e in har['log']['entries']
                     if e['request']['method'] == 'POST' and \
                     any(p['name'].startswith('SAML') for p in e['request'].get('postData', {}).get('params', []))]

    # Redact header and cookie values
    for entry in response_data:
        for t in ('request', 'response'):
            for category in ('cookies', 'headers'):
                for values_to_edit in entry[t][category]:
                    values_to_edit['value'] = "redacted"

    # Collect pages that match the entries found
    page_nums = {p['pageref'] for p in response_data}
    pages = [p for p in har['log']['pages'] if p['id'] in page_nums]

    # Create a second set of SAML data entries which are one day in the future.
    # This is to test having multiple entries in the file.
    second_response_entries = []

    for entry in response_data:
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

    out = {'log': {
        'pages': pages,
        'entries': response_data + second_response_entries}
    }

    with open(destination_file, 'w') as f:
        json.dump(out, f)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise ValueError("Incorrect number of arguments specified! Need only a source and destination file.")
    redact_har_file(*sys.argv[1:])
