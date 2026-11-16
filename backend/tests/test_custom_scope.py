import pytest
from fastapi import HTTPException
from argus.api import validate_custom_scope
from argus.models import Scope


def mk(**kw):
    return Scope(**{"targets": ["203.0.113.0/24"], "authorized_by": "Organizer", **kw})


def test_normal_custom_scope_is_accepted():
    validate_custom_scope(mk(targets=["203.0.113.0/24", "app.example.org", "http://10.0.0.5:8080"]))


def test_empty_targets_rejected():
    with pytest.raises(HTTPException):
        validate_custom_scope(mk(targets=[]))


def test_missing_authorizer_rejected():
    with pytest.raises(HTTPException):
        validate_custom_scope(mk(authorized_by="  "))


@pytest.mark.parametrize("t", ["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/15"])
def test_internet_sized_network_rejected(t):
    with pytest.raises(HTTPException):
        validate_custom_scope(mk(targets=[t]))


def test_slash16_is_the_largest_allowed():
    validate_custom_scope(mk(targets=["172.16.0.0/16"]))
