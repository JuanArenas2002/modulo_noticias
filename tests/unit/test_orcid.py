"""ORCID: formato, dígito de control (ISO 7064 MOD 11-2) y formas de entrada aceptadas."""
import pytest

from app.shared.orcid import checksum, normalize_orcid


def test_valid_orcids_and_input_forms():
    assert checksum("000000021825009") == "7"                                      # Josiah Carberry (ORCID demo)
    for raw in ("0000-0002-1825-0097", "https://orcid.org/0000-0002-1825-0097", "http://orcid.org/0000-0002-1825-0097",
                "orcid.org/0000-0002-1825-0097", " 0000000218250097 ", "0000 0002 1825 0097"):
        assert normalize_orcid(raw) == "0000-0002-1825-0097", raw
    assert normalize_orcid("0000-0002-1694-233x") == "0000-0002-1694-233X"         # dígito de control X


@pytest.mark.parametrize("bad", ["", "1234", "0000-0002-1825-0098", "0000-0002-1825-009X", "abcd-efgh-ijkl-mnop",
                                 "0000-0002-1825-00970", "https://evil.com/0000-0002-1825-0097"])
def test_invalid_orcids_are_rejected(bad):
    with pytest.raises(ValueError):
        normalize_orcid(bad)
