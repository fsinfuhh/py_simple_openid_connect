from simple_openid_connect import pkce


def test_get_code_challenge():
    PKCE_PAIRS = [
        # (verifier, challenge) pairs
        (
            "X1mcNAU_lfu25acaJoCQSyo4YyZc1NwaxWw7tNL7mffK0AXCS-lNBtisryb2",
            "V_nSilRCu0pt3eR-cH7LWru-rYwlTr3J2143tiwloCA",
        ),
        (
            "9ok-JCOrX1OkmCFy8wGq2UBTGgFkeEg5IGffzgKNfDrpO-AOJ-83J9IhXOqj",
            "ET7UYFBGIHCdYh9bLyeLqWiKEr3t3JCxMRNacq3NCGk",
        ),
        (
            "zDv_Uz7QRoYRgIdieHac1UIlDNPPQb8qVIwgLzFu66kHo2g92UfkoU8Vi91z",
            "iWLceDSH1e3G7NJ5eieiqpk9IgXPTgSUd8ivdbRZKII",
        ),
    ]
    for verifier, challenge in PKCE_PAIRS:
        assert pkce.get_code_challenge(verifier) == challenge, (
            "get_code_challenge() produced an unexpected challenge"
        )


def test_gen_pair_is_actual_pair():
    for _ in range(100):
        verifier, challenge = pkce.generate_pkce_pair()
        assert challenge == pkce.get_code_challenge(verifier), (
            "pkce.generate_pkce_pair() returned a pair whose challenge cannot be reproduced from the verifier"
        )
