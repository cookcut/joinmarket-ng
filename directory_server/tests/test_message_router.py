"""
Tests for message router, focusing on failed send cleanup.
"""

import pytest
from jmcore.models import MessageEnvelope, NetworkType, PeerInfo, PeerStatus
from jmcore.protocol import MessageType

from directory_server.message_router import MessageRouter
from directory_server.peer_registry import PeerRegistry


@pytest.fixture
def registry():
    return PeerRegistry(max_peers=100)


@pytest.fixture
def sample_peers(registry):
    """Create and register sample peers."""
    peers = []
    # Use different base characters for each peer to get unique onion addresses
    base_chars = ["a", "b", "c", "d", "e"]
    for i, char in enumerate(base_chars):
        peer = PeerInfo(
            nick=f"peer{i}",
            onion_address=f"{char * 56}.onion",
            port=5222,
            network=NetworkType.MAINNET,
            status=PeerStatus.HANDSHAKED,
        )
        registry.register(peer)
        peers.append(peer)
    return peers


class TestMessageRouterFailedSendCleanup:
    """Tests for cleanup behavior when sends fail."""

    @pytest.mark.anyio
    async def test_safe_send_calls_on_send_failed_callback(self, registry, sample_peers):
        """When a send fails, the on_send_failed callback should be invoked."""
        failed_peers = []

        async def failing_send(peer_key: str, data: bytes) -> None:
            raise ConnectionError("Connection closed")

        async def on_failed(peer_key: str) -> None:
            failed_peers.append(peer_key)

        router = MessageRouter(
            peer_registry=registry,
            send_callback=failing_send,
            on_send_failed=on_failed,
        )

        # Attempt to send - should fail and trigger callback
        await router._safe_send("peer0", b"test data", "peer0")

        assert "peer0" in failed_peers

    @pytest.mark.anyio
    async def test_safe_send_skips_already_failed_peers(self, registry, sample_peers):
        """Peers that have already failed should be skipped on subsequent attempts."""
        send_attempts = []

        async def failing_send(peer_key: str, data: bytes) -> None:
            send_attempts.append(peer_key)
            raise ConnectionError("Connection closed")

        router = MessageRouter(
            peer_registry=registry,
            send_callback=failing_send,
        )

        # First attempt - should try to send
        await router._safe_send("peer0", b"test data", "peer0")
        assert len(send_attempts) == 1

        # Second attempt - should skip because peer is in _failed_peers
        await router._safe_send("peer0", b"test data", "peer0")
        assert len(send_attempts) == 1  # No additional attempt

    @pytest.mark.anyio
    async def test_batched_broadcast_clears_failed_peers_on_new_broadcast(
        self, registry, sample_peers
    ):
        """Each new broadcast should clear the failed peers set."""
        send_attempts = []

        async def failing_send(peer_key: str, data: bytes) -> None:
            send_attempts.append(peer_key)
            raise ConnectionError("Connection closed")

        router = MessageRouter(
            peer_registry=registry,
            send_callback=failing_send,
        )

        targets = [(sample_peers[0].location_string, sample_peers[0].nick)]

        # First broadcast - peer fails
        await router._batched_broadcast(targets, b"test data")
        assert len(send_attempts) == 1

        # Second broadcast - should try again because _failed_peers was cleared
        await router._batched_broadcast(targets, b"test data")
        assert len(send_attempts) == 2

    @pytest.mark.anyio
    async def test_batched_broadcast_filters_failed_peers_within_batch(
        self, registry, sample_peers
    ):
        """Failed peers should be filtered out within the same broadcast."""
        send_attempts = []
        fail_peer = sample_peers[0].location_string

        async def selective_failing_send(peer_key: str, data: bytes) -> None:
            send_attempts.append(peer_key)
            if peer_key == fail_peer:
                raise ConnectionError("Connection closed")

        router = MessageRouter(
            peer_registry=registry,
            send_callback=selective_failing_send,
            broadcast_batch_size=2,  # Small batch to test filtering across batches
        )

        # Create targets with the failing peer appearing in multiple batches conceptually
        # (in practice they're unique, but the failed set should prevent retries)
        targets = [(p.location_string, p.nick) for p in sample_peers]

        await router._batched_broadcast(targets, b"test data")

        # Each peer should only be attempted once
        unique_attempts = set(send_attempts)
        assert len(unique_attempts) == len(send_attempts)

    @pytest.mark.anyio
    async def test_on_send_failed_callback_error_is_handled(self, registry, sample_peers):
        """Errors in the on_send_failed callback should not propagate."""

        async def failing_send(peer_key: str, data: bytes) -> None:
            raise ConnectionError("Connection closed")

        async def broken_callback(peer_key: str) -> None:
            raise RuntimeError("Callback error")

        router = MessageRouter(
            peer_registry=registry,
            send_callback=failing_send,
            on_send_failed=broken_callback,
        )

        # Should not raise despite callback error
        await router._safe_send("peer0", b"test data", "peer0")

    @pytest.mark.anyio
    async def test_successful_send_does_not_trigger_callback(self, registry, sample_peers):
        """Successful sends should not trigger the on_send_failed callback."""
        failed_peers = []

        async def successful_send(peer_key: str, data: bytes) -> None:
            pass  # Success

        async def on_failed(peer_key: str) -> None:
            failed_peers.append(peer_key)

        router = MessageRouter(
            peer_registry=registry,
            send_callback=successful_send,
            on_send_failed=on_failed,
        )

        await router._safe_send("peer0", b"test data", "peer0")

        assert len(failed_peers) == 0


class TestMessageRouterPrivateMessageFailedSend:
    """Tests for private message routing with failed sends."""

    @pytest.mark.anyio
    async def test_private_message_failure_triggers_cleanup(self, registry, sample_peers):
        """When private message routing fails, cleanup callback should be called."""
        failed_peers = []
        from_peer = sample_peers[0]
        to_peer = sample_peers[1]

        async def failing_send(peer_key: str, data: bytes) -> None:
            raise ConnectionError("Connection closed")

        async def on_failed(peer_key: str) -> None:
            failed_peers.append(peer_key)

        router = MessageRouter(
            peer_registry=registry,
            send_callback=failing_send,
            on_send_failed=on_failed,
        )

        # Create a valid private message (format: from_nick!to_nick!command message)
        payload = f"{from_peer.nick}!{to_peer.nick}!test message"
        envelope = MessageEnvelope(message_type=MessageType.PRIVMSG, payload=payload)

        await router._handle_private_message(envelope, from_peer.location_string)

        # The target peer should have been marked as failed
        assert to_peer.location_string in failed_peers
