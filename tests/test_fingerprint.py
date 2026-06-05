from arpex.fingerprint import FingerprintManager


def test_mac_normalization():

    fp = FingerprintManager()

    assert (
        fp.normalize_mac(
            "00-50-56-aa-bb-cc"
        )
        ==
        "00:50:56:AA:BB:CC"
    )


def test_invalid_mac():

    fp = FingerprintManager()

    assert (
        fp.normalize_mac(
            "not-a-mac"
        )
        is None
    )


def test_extract_oui():

    fp = FingerprintManager()

    assert (
        fp.extract_oui(
            "00:50:56:AA:BB:CC"
        )
        ==
        "005056"
    )

def test_vendor_lookup():

    fp = FingerprintManager()

    fp.load_oui_database()

    vendor = fp.lookup_vendor(
        "00:50:56:AA:BB:CC"
    )

    assert vendor == "VMware"


def test_unknown_vendor():

    fp = FingerprintManager()

    fp.load_oui_database()

    vendor = fp.lookup_vendor(
        "AA:BB:CC:DD:EE:FF"
    )

    assert vendor == "Unknown"


def test_invalid_vendor_lookup():

    fp = FingerprintManager()

    fp.load_oui_database()

    vendor = fp.lookup_vendor(
        "invalid"
    )

    assert vendor == "Unknown"