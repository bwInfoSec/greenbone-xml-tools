# greenbone-xml-tools

Here you will find a number of tools that deal with greenbone's XML scan reports. 

## Usage
To use this code you'll need to install the python packages listed in [requirements.txt](requirements.txt).

``` sh
pip install -r requirements.txt
```

The usage of a [venv](https://docs.python.org/3/library/venv.html) is strongly recommended.

## Content 

- **[greenbone_parser.py](greenbone_parser.py)**: A parser that extracts the useful information from a greenbone XML scan report. That result can be saved as JSON to further process the data. Usually the extracted JSON is minimum an order of magnitude smaller than the original XML which is also beneficial. Have a look into the codes `__main__` for a usage example.


## Licensing

This work is licensed under the [EUPL 1.2](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12).

## Contribution
If you want to contribute feel free to do so by creating a pull request on [github](https://github.com/bwInfoSec/greenbone-xml-tools).
