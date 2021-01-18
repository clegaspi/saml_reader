# SAML Reader

## **IMPORTANT**
Please **DO NOT** add any personally identifiable information (PII) when reporting an issue.

This means **DO NOT** upload any SAML data, even if it is yours. I don't want to be responsible
for it. :)

## What is this tool?
This tool parses SAML responses, gathering relevant info for diagnosing issues with federated authentication for Cloud.
There is some extra checks for MDB Cloud, but not many so far.

### Installation

One of the tools used in this package requires `xmlsec`, which requires some libraries be installed on your system. See [this page](https://pypi.org/project/xmlsec/) for details on the required packages. For Mac, they can be installed by running [Homebrew](https://brew.sh/):

```
brew install libxml2 libxmlsec1 pkg-config
```

To install the actual package once the dependencies have been installed:

1. Clone repository
2. If you wish to run this package in an environment such as [virtualenv](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/) or [Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/getting-started.html), create the environment of your choice with Python 3.6+ and activate it. I always recommend installing in an environment, but if you wish to install the package globally, skip to step 3.
3. In root directory of the repository, run:
```bash
pip install .
```
4. Run the command line interface by running `saml_reader`

This tool requires a few packages for parsing the data.

### Updating the package

As this software is in its infancy, updates will be made quickly as bugs are discovered and improvements are made. To get the latest version, from the root of the repository, run:

```
git pull
pip install .
```

This should uninstall the old version and install the new.

### Running the CLI

This tool can accept a SAML response as properly-formatted XML or
a base64-encoded string, or it can be extracted directly from a HAR file dump. 
The data can be input from a file, from the system clipboard,
or from a Unix pipe.

## Data Sources
#### Reading from a file with different types

```bash
saml_reader /path/to/file.xml   # XML is default type
saml_reader /path/to/base64.txt --type base64   # base64 requires flag
saml_reader /path/to/harfile.har --type har     # har requires flag
```

#### Reading from clipboard

If you have the xml, base64, or har data in your system clipboard, run:

```bash
saml_reader --clip --type <xml, base64, har>
```

The `--type` flag is not required for an XML file.

#### Reading from pipe

If you prefer piping or have been doing your own parsing on the command line:

```
cat file.xml | saml_reader
cat base64.txt | saml_reader --type base64
cat file.har | saml_reader --type har
```

You can specify `saml_reader --stdin` but it is not required. 

## Other command line options

By default, the application will only output the results of validation
tests. There are some extra options to expand the tests and the information
that is output by the program.

### `--summary`

This flag will print a full summary of key parameters pulled directly from the SAML 
response and certificate.

### `--summary-only`

This will only print the summary and skip any validation tests. Cannot be specified
with `--compare`

### `--compare`

This will allow the user to input expected values to compare with the SAML response.
SAML Reader will prompt for each value in the terminal. Values can
be skipped by pressing Enter without inputting a value. Example:

```
Customer First Name: Sam
Customer Last Name: Ell
Customer Email Address: sam.ell@mydomain.com
MongoDB Assertion Consumer Service URL: https://auth.mongodb.com/sso/saml2/01234abcDE56789ZyXwv
MongoDB Audience URL: https://www.okta.com/saml2/service-provider/abcdefghijklmnopqrst
Domain(s) associated with IdP:
1. foo.com
2. bar.net
3. mydomain.com
4. 
IdP Issuer URI: Issuer_URI_Here
Encryption Algorithm (SHA1 or SHA256): SHA256
Is customer expecting role mapping (y/N): y
Expected role mapping group names (if unknown, leave blank):
1. Test Group Name
2.
```
All values will be validated to see if they match expected values for MongoDB Cloud.
If an attribute does not pass validation, you will be asked to re-enter it or skip it.

Alternatively, this option will accept a single argument as a path to a JSON file containing the
comparison values in the format:

```javascript
{
  "firstName": "Sam",
  "lastName": "Ell",
  "email": "sam.ell@mydomain.com",
  "issuer": "Issuer URI here",
  "acs": "Assertion Consumer Service URL here",
  "audience": "Audience URL here",
  "encryption": "Must be 'SHA1' or 'SHA256'",
  "domains": ["foo.com", "bar.net", "mydomain.com"],
  "role_mapping_expected": "Y",
  "memberOf": ["Test Group Name"]
} 
```

Any value can be omitted or substituted with `null` to be ignored. 
An empty string (`""`) or empty list (`[]`) will be interpreted as an invalid value.

## Reporting issues

Because this tool inherently deals with personally identifiable information (PII)
and security information, this bears repeating...

**IMPORTANT: Please DO NOT add any personally**
**identifiable information (PII) when reporting an issue.**

This means **DO NOT** upload any SAML data, even if it is yours.

That said, thank you in advance for reporting any issues that you find while using
this tool. This tool is in its infancy, so it's sure to have issues and non-graceful
handling of errors. To report an issue, please open an issue on this repository,
describing the issue you are experiencing and one of the maintainers will look into the issue.

## Contributing

I do not have any specific requirements for contributing at this time, other than
that I am using Google-style docstrings. Please feel free to open a pull request!