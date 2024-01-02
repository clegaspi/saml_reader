# SAML Reader

## **IMPORTANT**

Please **DO NOT** add any personally identifiable information (PII) when reporting an issue.

This means **DO NOT** upload any SAML data, even if it is yours. I don't want to be responsible
for it. :)

## Table of Contents

- [SAML Reader](#saml-reader)
  - [**IMPORTANT**](#important)
  - [Table of Contents](#table-of-contents)
  - [What is this tool?](#what-is-this-tool)
  - [Installation](#installation)
    - [Dependencies for `xmlsec`](#dependencies-for-xmlsec)
    - [Installing from PyPI](#installing-from-pypi)
    - [Installing from GitHub source](#installing-from-github-source)
    - [Workaround for Apple M Chips](#workaround-for-apple-m-chips)
  - [Updating the package](#updating-the-package)
    - [From PyPI](#from-pypi)
    - [From GitHub source](#from-github-source)
  - [Running the web app](#running-the-web-app)
  - [Running the CLI](#running-the-cli)
    - [Data Sources](#data-sources)
      - [**Reading from a file**](#reading-from-a-file)
      - [**Reading from clipboard**](#reading-from-clipboard)
      - [**Reading from pipe**](#reading-from-pipe)
    - [Other command line options](#other-command-line-options)
      - [`--summary`](#--summary)
      - [`--summary-only`](#--summary-only)
      - [`--compare`](#--compare)
  - [Reporting issues](#reporting-issues)
  - [Contributing](#contributing)

## What is this tool?

This tool parses SAML responses, gathering relevant info for diagnosing issues with federated authentication for MongoDB Cloud.

---

## Installation

### Dependencies for `xmlsec`

One of the tools used in this package requires `xmlsec`, which requires some libraries be installed on your system. See [this page](https://pypi.org/project/xmlsec/) for details on the required packages. For Mac, they can be installed by running [Homebrew](https://brew.sh/):

```
brew install libxml2 libxmlsec1 pkg-config
```

For Windows, installing the `xmlsec` package from PyPI already has these dependencies pre-built into the installation process for the package, so there should be no need to install them separately.

For Apple M Chips a workaround will be outlined below.

### Installing from PyPI

To install SAML Reader from PyPI:

1. It is **highly recommended** that this package be run in a Python virtual environment such as [virtualenv](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/) or [Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/getting-started.html). Please follow one of the previous links to learn how to create a Python environment of your choice. Create the environment with Python 3.6-3.10 and activate it. **SAML Reader is not currently compatible with Python 3.11+.** I do not recommend installing this directly into your system's global environment. There is just so much that can go wrong.
2. Install the package from PyPI:

```bash
pip install saml_reader
```
3. Downgrade Werkzeug to `2.2.2` with `pip install Werkzeug==2.2.2` as the current release version introduces a breaking change and this version negates that change until a later Web Application Framework can be utilised. This is detailed in the Github issues section for [issue 85](https://github.com/clegaspi/saml_reader/issues/85)
4. Run the command line interface by running `saml_reader` with options specified below.

### Installing from GitHub source

If you wish to install from the GitHub source:

1. Clone the repository locally with `git clone`.
2. Create a virtual environment such as [virtualenv](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/) or [Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/getting-started.html) using Python 3.9+ and activate it.
3. In the root directory of the repository, run `pip install .` to install the package. If you are planning to make changes to the package, run `pip install -e .` instead to install the package in editable mode.
4. Run the command line interface by running `saml_reader` with options specified below.

## Updating the package

As this software is in its infancy, updates will be made quickly as bugs are discovered and improvements are made.

### From PyPI

To get the latest version, run:

```
pip install --upgrade saml_reader
```

This should uninstall the old version and install the new.

### From GitHub source

To pull down the latest version:

1. Checkout `master` branch with `git checkout master`.
2. Run `git pull` to pull down the latest changes.
3. If you installed in editable mode, you should be good to go. If you did not install in editable mode, run `pip install .` in the root directory of the repository.

---

### Workaround for Apple M Chips

There is presently an issue with `libxmlsec1` versions => `1.3.0` and Apple Silicon which results in an ungraceful failure in a required dependency `lxml` when `cpython` attempts to compile it. The following workaround has been tested successfully with a Macbook Pro M1 Pro and Python 3.10+. This involves downgrading `xmlsec` to a known working version (`1.2.37`).

1. Install the required `xmlsec` dependencies above.
2. Clone the repository locally with `git clone`.
3. Create a virtual environment such as [virtualenv](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/) or [Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/getting-started.html) using Python 3.9+ and activate it.
4. `brew edit libxmlsec1` and replace the entire contents of the brew package with the following [gist](https://raw.githubusercontent.com/Homebrew/homebrew-core/7f35e6ede954326a10949891af2dba47bbe1fc17/Formula/libxmlsec1.rb)
5. `brew unlink libxmlsec1` and `brew uninstall libxmlsec1`
6. In your shell `rc` file (`.bashrc`, `.zshrc`, etc.), set the environment variable `HOMEBREW_NO_INSTALL_FROM_API` to `1`.
7. Force a clean installation with `brew install /opt/homebrew/Library/Taps/homebrew/homebrew-core/Formula/libxmlsec1.rb`
8. Trigger a clean installation of the pip package with `pip install . --no-cache-dir`.
9. Downgrade the version of `Werkzeug` from `3.0.1` to `2.2.2` using `pip install Werkzeug==2.2.2`.
10. Remove `HOMEBREW_NO_INSTALL_FROM_API` from your shell `rc` file.
11. (optional) To keep `brew` from upgrading the package, run `brew pin libxmlsec1`.

Thank you to @josh-allan for identifying this workaround.

## Running the web app

This tool can be run locally as a web app. You simply need to run:

```
saml_web_app
```

This will run the web app, serving it on `localhost` and port `8050`. Your default browser will
open automatically to http://localhost:8050. There are a couple of arguments that the web app will
take:

- `--host <host>`: this lets you specify host/IP address where the web app is listening. Default is `localhost`
- `--port <port>`: this lets you specify port where the web app is listening. Default is `8050`
- `--no-open-browser`: suppresses opening the web browser automatically
- `--keep-alive`: keeps the web server running indefinitely, or until killed with Ctrl+C. The server will time out after 30 minutes otherwise.
- `--version`: returns the installed version and exits
- `--help`: displays the help menu

When you navigate to the web app, the `Analyze SAML` link is the only one that currently has any functionality. You enter the SAML data on the left side and specify any comparison values you wish to include on the right side. Once you do that, click `Analyze` and the output will appear.

When you are done using the web app, please be sure to close the web server by pressing Ctrl+C in the terminal where you ran the web app. If you did not specify `--keep-alive`, the server will automatically terminate after 30 minutes.

---

## Running the CLI

This tool can accept a SAML response as properly-formatted XML or
a base64-encoded string, or it can be extracted directly from a HAR file dump.
The data can be input from a file, from the system clipboard,
or from a Unix pipe.

### Data Sources

You can read from a number of different sources in a number of different formats.

#### **Reading from a file**

You with different types

```bash
saml_reader /path/to/file.xml   # XML is default type
saml_reader /path/to/base64.txt --type base64   # base64 requires flag
saml_reader /path/to/harfile.har --type har     # har requires flag
```

#### **Reading from clipboard**

If you have the xml, base64, or har data in your system clipboard, run:

```bash
saml_reader --clip --type <xml, base64, har>
```

The `--type` flag is not required for an XML file.

#### **Reading from pipe**

If you prefer piping or have been doing your own parsing on the command line:

```
cat file.xml | saml_reader
cat base64.txt | saml_reader --type base64
cat file.har | saml_reader --type har
```

You can specify `saml_reader --stdin` but it is not required.

### Other command line options

By default, the application will only output the results of validation
tests. There are some extra options to expand the tests and the information
that is output by the program.

#### `--summary`

This flag will print a full summary of key parameters pulled directly from the SAML
response and certificate.

#### `--summary-only`

This will only print the summary and skip any validation tests. Cannot be specified
with `--compare`

#### `--compare`

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
Signing Certificate Expiration Date (MM/DD/YYYY): 01/31/2021
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
  "cert_expiration": "Date in MM/DD/YYYY format",
  "acs": "Assertion Consumer Service URL here",
  "audience": "Audience URL here",
  "encryption": "Must be 'SHA1' or 'SHA256'",
  "domains": ["foo.com", "bar.net", "mydomain.com"],
  "role_mapping_expected": "Must be 'Y' or 'N'",
  "memberOf": ["Test Group Name"]
}
```

Note that `domains` and `memberOf` must be lists. Any value can be omitted or substituted with `null` to be ignored.
An empty string (`""`) or empty list (`[]`) will be interpreted as an invalid value.

---

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

As the architecture has evolved, I plan to create a document with more information on
the structure of the application and how to contribute.
