import pytest
from endpoints import listpubkeys, refresh


@pytest.mark.xfail(strict=True) # TODO: Fix, see #167
def test_no_keys_initially(setup_kms):
    status_code, pubkeys = listpubkeys(setup_kms["url"])
    assert status_code == 200
    assert len(pubkeys["keys"]) == 0


def test_refresh_key_appears(setup_kms):
    refresh(setup_kms["url"])
    while True:
        status_code, pubkeys = listpubkeys(setup_kms["url"])
        print("listpubkeys result: ", status_code, pubkeys)
        if status_code != 202:
            break
    assert status_code == 200
    assert len(pubkeys) == 1


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-s"])