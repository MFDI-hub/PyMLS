from pymls.protocol.validations import commit_path_required
from pymls.protocol.data_structures import (
    AddProposal,
    UpdateProposal,
    RemoveProposal,
    PreSharedKeyProposal,
    GroupContextExtensionsProposal,
)


def test_commit_path_required_psk_only():
    # PSK-only should not require an UpdatePath
    proposals = [PreSharedKeyProposal(b"psk-id-1")]
    assert commit_path_required(proposals) is False


def test_commit_path_required_update_remove_gce():
    # Update, Remove, and GroupContextExtensions each require a path
    assert commit_path_required([UpdateProposal(b"x")]) is True
    assert commit_path_required([RemoveProposal(0)]) is True
    assert commit_path_required([GroupContextExtensionsProposal(b"\x00\x00")]) is True


