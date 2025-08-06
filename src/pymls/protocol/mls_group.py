from .data_structures import Proposal, Welcome, GroupContext, AddProposal, UpdateProposal, RemoveProposal, Sender, Signature, Commit
from .key_packages import KeyPackage, LeafNode
from .messages import PublicMessage, PrivateMessage
from .ratchet_tree import RatchetTree
from .key_schedule import KeySchedule
from ..crypto.crypto_provider import CryptoProvider


class MLSGroup:
    def __init__(self, group_id: bytes, crypto_provider: CryptoProvider, own_leaf_index: int):
        self._group_id = group_id
        self._crypto_provider = crypto_provider
        self._ratchet_tree = RatchetTree(crypto_provider)
        self._group_context: GroupContext | None = None
        self._key_schedule: KeySchedule | None = None
        self._interim_transcript_hash: bytes | None = None
        self._confirmed_transcript_hash: bytes | None = None
        self._pending_proposals: list[Proposal] = []
        self._own_leaf_index = own_leaf_index

    @classmethod
    def create(cls, group_id: bytes, key_package: KeyPackage, crypto_provider: CryptoProvider) -> "MLSGroup":
        group = cls(group_id, crypto_provider, 0)
        group._ratchet_tree.add_leaf(key_package)
        # This is a simplification. The initial secrets and group context would be derived differently.
        init_secret = crypto_provider.kdf_extract(b"", b"")
        commit_secret = crypto_provider.kdf_extract(b"", b"")
        group._group_context = GroupContext(group_id, 0, group._ratchet_tree.calculate_tree_hash(), b"")
        group._key_schedule = KeySchedule(init_secret, commit_secret, group._group_context, None, crypto_provider)
        return group

    @classmethod
    def from_welcome(cls, welcome: Welcome, key_package: KeyPackage, crypto_provider: CryptoProvider) -> "MLSGroup":
        # This is a simplification. We would need to decrypt the welcome message to get the initial group state.
        group = cls(welcome.group_info.group_context.group_id, crypto_provider, -1)
        # The leaf index would be determined from the welcome message.
        group._ratchet_tree.merge_update_path(welcome.encrypted_group_info)
        # The key schedule would be derived from the welcome message.
        return group

    def create_add_proposal(self, key_package: KeyPackage, signing_key: bytes) -> PublicMessage:
        proposal = AddProposal(key_package.serialize())
        proposal_bytes = proposal.serialize()
        signature = self._crypto_provider.sign(signing_key, proposal_bytes)
        return PublicMessage(proposal_bytes, Signature(signature))

    def create_update_proposal(self, leaf_node: LeafNode, signing_key: bytes) -> PublicMessage:
        proposal = UpdateProposal(leaf_node.serialize())
        proposal_bytes = proposal.serialize()
        signature = self._crypto_provider.sign(signing_key, proposal_bytes)
        return PublicMessage(proposal_bytes, Signature(signature))

    def create_remove_proposal(self, removed_index: int, signing_key: bytes) -> PublicMessage:
        proposal = RemoveProposal(removed_index)
        proposal_bytes = proposal.serialize()
        signature = self._crypto_provider.sign(signing_key, proposal_bytes)
        return PublicMessage(proposal_bytes, Signature(signature))

    def process_proposal(self, message: PublicMessage, sender: Sender) -> None:
        sender_leaf_node = self._ratchet_tree.get_node(sender.sender * 2).leaf_node
        if not sender_leaf_node:
            raise ValueError(f"No leaf node found for sender index {sender.sender}")

        self._crypto_provider.verify(
            sender_leaf_node.signature_key,
            message.content,
            message.signature.value
        )

        proposal = Proposal.deserialize(message.content)
        self._pending_proposals.append(proposal)

    def create_commit(self, signing_key: bytes) -> tuple[PrivateMessage, list[Welcome]]:
        # This is a simplification. It handles a self-update and pending proposals.
        removes = [p.removed for p in self._pending_proposals if isinstance(p, RemoveProposal)]
        adds_kps = [KeyPackage.deserialize(p.key_package) for p in self._pending_proposals if isinstance(p, AddProposal)]
        # This is not fully correct, as we should apply these to the tree before creating the path.

        # Create an update path for the committer (ourselves)
        own_node = self._ratchet_tree.get_node(self._own_leaf_index * 2)
        # In a real update, this leaf node would be regenerated with new credentials
        new_leaf_node = own_node.leaf_node
        update_path, commit_secret = self._ratchet_tree.create_update_path(self._own_leaf_index, new_leaf_node)

        # Construct and sign the commit
        temp_commit = Commit(
            path=update_path,
            removes=removes,
            adds=[kp.serialize() for kp in adds_kps],
            signature=Signature(b"")  # Empty signature for serialization
        )
        commit_bytes_for_signing = temp_commit.serialize()
        signature_value = self._crypto_provider.sign(signing_key, commit_bytes_for_signing)
        commit = Commit(temp_commit.path, temp_commit.removes, temp_commit.adds, Signature(signature_value))

        # Advance epoch and derive new key schedule
        new_epoch = self._group_context.epoch + 1
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        # Transcript hashes are not fully implemented, using placeholders.
        new_group_context = GroupContext(self._group_id, new_epoch, tree_hash, b"confirmed_transcript_hash")

        self._key_schedule = KeySchedule(self._key_schedule.resumption_psk, commit_secret, new_group_context, None, self._crypto_provider)
        self._group_context = new_group_context
        self._pending_proposals = []

        # Encrypt commit message
        commit_bytes = commit.serialize()
        encrypted_commit = self._crypto_provider.aead_encrypt(self._key_schedule.encryption_secret, b"", commit_bytes, b"")
        return PrivateMessage(encrypted_commit, b""), []

    def process_commit(self, message: PrivateMessage, sender_index: int) -> None:
        # Decrypt commit using the current epoch's encryption_secret
        commit_bytes = self._crypto_provider.aead_decrypt(self._key_schedule.encryption_secret, b"", message.ciphertext, b"")
        commit = Commit.deserialize(commit_bytes)

        # Verify signature
        sender_leaf_node = self._ratchet_tree.get_node(sender_index * 2).leaf_node
        if not sender_leaf_node:
            raise ValueError(f"No leaf node for committer index {sender_index}")

        temp_commit = Commit(commit.path, commit.removes, commit.adds, Signature(b""))
        commit_bytes_for_signing = temp_commit.serialize()
        self._crypto_provider.verify(sender_leaf_node.signature_key, commit_bytes_for_signing, commit.signature.value)

        # Apply changes and derive new key schedule
        if commit.path:
            commit_secret = self._ratchet_tree.merge_update_path(commit.path, sender_index)

            # Advance epoch
            new_epoch = self._group_context.epoch + 1
            tree_hash = self._ratchet_tree.calculate_tree_hash()
            new_group_context = GroupContext(self._group_id, new_epoch, tree_hash, b"confirmed_transcript_hash")

            self._key_schedule = KeySchedule(self._key_schedule.resumption_psk, commit_secret, new_group_context, None, self._crypto_provider)
            self._group_context = new_group_context
        else:
            raise NotImplementedError("Processing commits without a path is not supported yet.")

    def protect(self, app_data: bytes) -> PrivateMessage:
        key, nonce = self._key_schedule.derive_sender_secrets(self._own_leaf_index)
        ciphertext = self._crypto_provider.aead_encrypt(key, nonce, app_data, b"")
        return PrivateMessage(ciphertext, b"")

    def unprotect(self, message: PrivateMessage, sender_index: int) -> bytes:
        # This is a simplification. We need to know the sender's leaf index.
        key, nonce = self._key_schedule.derive_sender_secrets(sender_index)
        return self._crypto_provider.aead_decrypt(key, nonce, message.ciphertext, b"")

    def get_epoch(self) -> int:
        return self._group_context.epoch

    def get_group_id(self) -> bytes:
        return self._group_id
