from simple_openid import discovery


def test_mafiasi_identity(openid_provider_configs):
    discovery.discover_configuration_from_issuer(
        "https://identity.mafiasi.de/auth/realms/mafiasi/"
    )


def test_google(openid_provider_configs):
    discovery.discover_configuration_from_issuer("https://accounts.google.com/")
