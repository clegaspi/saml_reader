## SAML Reader

This tool parses SAML responses, gathering relevant info for diagnosing issues with federated authentication for Cloud.
There is some extra checks for MDB Cloud, but not many so far.

### Install

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

This tool requires a few packages for parsing.

### Running the CLI

This tool can accept a SAML response as properly-formatted XML or
a base64-encoded string, or it can be extracted directly from a HAR file dump. 
The data can be input from a file, from the system clipboard,
or from a Unix pipe.

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
