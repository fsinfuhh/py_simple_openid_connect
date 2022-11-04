import unittest

from simple_openid import discovery


class DiscoveryTestCase(unittest.TestCase):
    def test_mafiasi_identity(self):
        discovery.discover_configuration_from_issuer(
            "https://identity.mafiasi.de/auth/realms/mafiasi/"
        )

    def test_google(self):
        discovery.discover_configuration_from_issuer("https://accounts.google.com/")
