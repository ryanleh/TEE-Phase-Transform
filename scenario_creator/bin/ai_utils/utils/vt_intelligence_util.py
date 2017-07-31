import urllib
import urllib2
import json
import time
import logging


class VTIntelligenceUtilClass():

    INTELLIGENCE_SEARCH_URL = 'https://www.virustotal.com/intelligence/search/programmatic/'

    @staticmethod
    def get_matching_files(search, apiKey):
        """Get a page of files matching a given Intelligence search.

        Args:
          search: a VirusTotal Intelligence search phrase. More about Intelligence
            searches at: https://www.virustotal.com/intelligence/help/
          page: a token indicating the page of file results that should be retrieved.

        Returns:
          Tuple with a token to retrieve the next page of results and a list of sha256
          hashes of files matching the given search conditions.

        Raises:
          InvalidQueryError: if the Intelligence query performed was not valid.
        """
        logging.info('Getting matching files...')
        response = None
        attempts = 0
        parameters = {'query': search, 'apikey': apiKey}
        data = urllib.urlencode(parameters)
        request = urllib2.Request(VTIntelligenceUtilClass.INTELLIGENCE_SEARCH_URL, data)
        while attempts < 10:
            try:
                response = urllib2.urlopen(request).read()
                break
            except Exception:
                attempts += 1
                time.sleep(1)
        if not response:
            return None

        try:
            response_dict = json.loads(response)
        except ValueError:
            return None

        if not response_dict.get('result'):
            raise Exception("Virus Total returned an error. Check your query: {0}".format(response_dict.get('error')))

        hashes = response_dict.get('hashes', [])
        return hashes
