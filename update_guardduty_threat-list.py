#!/usr/bin/env python
""" Download the latest OTX reputation list, upload to S3, and update GuardDuty to use it

https://github.com/UranusBytes/icinga-plugins

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
"""

__author__ = "Jeremy Phillips"
__contact__ = "jeremy@uranusbytes.com"
__license__ = "GPLv2"
__version__ = "0.1.0"

import sys
import requests
from io import BytesIO
import gzip
import signal
from datetime import datetime
import logging
import boto3
import traceback

# Constants
###############################################################################
_STDERR_OUTPUT_LEVEL = logging.DEBUG  # Leave at logging.CRITICAL unless doing debugging
_PRINT_STACKTRACE_ON_ERROR = True  # Show stacktrace to stderr on error
# Learn about GuardDuty threat lists https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload_lists.html
_THREATLISTS = [
  {
    'list_name': 'OTX_Reputation',
    'list_url': 'https://reputation.alienvault.com/reputation.generic.gz',
    'list_format': 'TXT'
  }
]
_THREATLIST_S3_BUCKET = 'myBucket'
_THREATLIST_S3_KEY_PATH = 'myKeyPath'  # Without trailing or proceeding slash
_AWS_PROFILE = None  # Set to None to not use a profile (default, ec2 metadata, env vars, etc...)
_AWS_REGIONS = boto3.Session().get_available_regions(service_name='guardduty', partition_name='aws')


# Functions
###############################################################################
def _get_logger():
  _root_logger = logging.getLogger()
  _root_logger.setLevel(logging.DEBUG)
  _formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  _stderr_logger = logging.StreamHandler()
  _stderr_logger.setFormatter(_formatter)
  _stderr_logger.setLevel(_STDERR_OUTPUT_LEVEL)
  _root_logger.addHandler(_stderr_logger)
  _root_logger.info('Logger to StdErr Setup; root logger disabled')
  # Disable noisy libraries
  logging.getLogger("urllib3").setLevel(logging.WARNING)
  logging.getLogger("botocore").setLevel(logging.WARNING)
  return _root_logger


def _download_and_decompress_threatlist(_threatlist_url):
  try:
    _logger.info('Download latest threatlist: {0}'.format(_threatlist_url))
    _response = requests.get(_threatlist_url, stream=True)
    _logger.debug('Response: {0}'.format(_response))
    _compressed_file = BytesIO()
    _compressed_file.write(_response.raw.data)
    _compressed_file.seek(0)
    _decompressed_file = gzip.GzipFile(fileobj=_compressed_file, mode='rb')
    _threatlist_string = _decompressed_file.read()
    return _threatlist_string
  except Exception as err:
    _print_stacktrace(err)
    _logger.warning('Something failed downloading threatlist: {0}'.format(_threatlist_url))
    exit(1)


def _upload_threatlist(_list_name, _threatlist):
  try:
    _logger.info('Upload threatlist to S3')
    _s3_client = _get_aws_client(_service_name='s3', _aws_region=None)
    _response = _s3_client.put_object(
      Body=_threatlist,
      Bucket=_THREATLIST_S3_BUCKET,
      Key='{0}/{1}.txt'.format(_THREATLIST_S3_KEY_PATH, _list_name)
    )
    _logger.debug('Response: {0}'.format(_response))
    return
  except Exception as err:
    _print_stacktrace(err)
    _logger.warning('Something failed uploading threatlist to s3')
    exit(1)


def _reformat_threatlist(_threatlist):
  try:
    _logger.info('Reformat threat list to TXT format')
    _reformated_threatlist = []
    for _line in _threatlist.splitlines():
      _line_string = _line.decode('utf8').strip()
      if _line_string[:1] == '#':
        # Comment
        continue
      elif len(_line_string) == 0:
        # Empty line
        continue
      _reformated_threatlist.append(_line_string.split('#')[0].strip())

    return '\n'.join(_reformated_threatlist)
  except Exception as err:
    _print_stacktrace(err)
    _logger.warning('Something failed reformatting threatlist')
    exit(1)


def _refresh_guardduty_threatlist(_list_dict, _aws_region):
  try:
    # expects a dictionary representing the threat list.
    # {'list_name':_list_name, 'list_url':_list_url, 'list_format':_list_format}
    _logger.info('Refresh GuardDuty Threatlist - Region {0}'.format(_aws_region))
    _guardduty_client = _get_aws_client(_service_name='guardduty', _aws_region=_aws_region)

    _response = _guardduty_client.list_detectors(
      MaxResults=10,
    )
    # Each region,account tuple can only have 1 detector, so we grab that.
    _detectorId = _response['DetectorIds'][0]
    _response = _guardduty_client.list_threat_intel_sets(
      DetectorId=_detectorId,
      MaxResults=10,
    )
    if len(_response['ThreatIntelSetIds']) == 0:
      _logger.warning('No threatlist found in region {0}'.format(_aws_region))
      return
    elif len(_response['ThreatIntelSetIds']) > len(_THREATLISTS):
      _logger.warning('Region {0} has more threatlists configured than script defines.'.format(_aws_region))
      return
    _threatIntelSetId = _response['ThreatIntelSetIds'][0]
    _location = "https://s3.amazonaws.com/{0}/{1}/{2}.txt".format(_THREATLIST_S3_BUCKET, _THREATLIST_S3_KEY_PATH,
                                                                  _list_dict['list_name'])
    _revised_threat_set_name = '{0}_{1}'.format(_list_dict['list_name'],
                                                datetime.now().strftime("%Y%b%d_%H%M").upper())
    _response = _guardduty_client.update_threat_intel_set(
      Activate=True,
      DetectorId=_detectorId,
      Location=_location,
      Name=_revised_threat_set_name,
      ThreatIntelSetId=_threatIntelSetId
    )
    return
  except Exception as err:
    _print_stacktrace(err)
    _logger.warning('Something failed while updating threatlist')
    exit(1)


def _signal_handler(_signal, _frame):
  print("ERROR: SIGINT received.")
  sys.exit(3)


def _get_aws_client(_service_name, _aws_region):
  try:
    _logger.info('Get AWS client')
    _session_args = {}
    if _aws_region is not None:
      _session_args['region_name'] = _aws_region
    if _AWS_PROFILE is not None:
      _session_args['profile_name'] = _AWS_PROFILE

    _logger.debug('Session args: {0}'.format(_session_args))
    _session = boto3.Session(**_session_args)
    _client = _session.client(service_name=_service_name)
    _logger.info('AWS client created')
    return _client
  except Exception as err:
    _print_stacktrace(err)
    _logger.critical('Unknown error getting AWS client')
    exit(1)


def _print_stacktrace(_stacktrace):
  if _PRINT_STACKTRACE_ON_ERROR:
    traceback.print_exc(file=sys.stderr)


# Main
###############################################################################
def _main():
  _logger.info('Begin main')
  for _list_dict in _THREATLISTS:
    _logger.info('Threat List: {0}'.format(_list_dict))
    _threatlist = _download_and_decompress_threatlist(_list_dict['list_url'])
    _threatlist = _reformat_threatlist(_threatlist)
    _upload_threatlist(_list_dict['list_name'], _threatlist)

  _logger.info('Refresh AWS GuardDuty to newly uploaded threat list')
  for _aws_region in _AWS_REGIONS:
    for _list_dict in _THREATLISTS:
      _logger.info('AWS Region: {0}  Threat List: {1}'.format(_aws_region, _list_dict))
      _refresh_guardduty_threatlist(_list_dict, _aws_region)
  _logger.info('Finish main')
  return


if __name__ == "__main__":
  try:
    signal.signal(signal.SIGINT, _signal_handler)
    _logger = _get_logger()
    _main()
  except Exception as mainErr:
    _print_stacktrace(mainErr)
    _logger.critical('Unknown error in main')
    exit(1)
