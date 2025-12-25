import contextlib
import json
from unittest.mock import AsyncMock, patch

import pytest

from jmcore.directory_client import DirectoryClient, MessageType
from jmcore.protocol import FEATURE_PEERLIST_FEATURES


@pytest.mark.asyncio
async def test_get_peerlist_with_features_logs_correctly():
    """Test that get_peerlist_with_features logs the correct message."""
    from loguru import logger

    # Capture logs
    logs = []
    logger.add(lambda msg: logs.append(msg))

    # Mock the connection
    mock_connection = AsyncMock()

    # Setup the response
    response_data = {
        "type": MessageType.PEERLIST.value,
        "line": f"nick1;location1;F:{FEATURE_PEERLIST_FEATURES}",
    }
    mock_connection.receive.return_value = json.dumps(response_data).encode("utf-8")

    # Initialize client
    client = DirectoryClient("host", 1234, "mainnet")
    client.connection = mock_connection

    # Run the method
    peers = await client.get_peerlist_with_features()

    # Verify the log message
    log_text = "".join(str(log) for log in logs)
    assert "Sending GETPEERLIST request" in log_text
    assert "with features support" not in log_text

    # Verify the request was sent
    mock_connection.send.assert_called_once()
    sent_msg = json.loads(mock_connection.send.call_args[0][0].decode("utf-8"))
    assert sent_msg["type"] == MessageType.GETPEERLIST.value
    assert sent_msg["line"] == ""

    # Verify return value
    assert len(peers) == 1
    nick, loc, features = peers[0]
    assert nick == "nick1"
    assert loc == "location1"
    assert features.supports_peerlist_features()


@pytest.mark.asyncio
async def test_privmsg_fidelity_bond_taker_nick():
    """
    Test that when receiving an offer via PRIVMSG, the fidelity bond is verified
    against the recipient's nick (us), not the maker's nick.
    """
    import asyncio

    # Setup
    client = DirectoryClient("host", 1234, "mainnet")
    client.nick = "MyNick"
    client.connection = AsyncMock()

    # Maker sending the offer
    maker_nick = "MakerNick"
    offer_msg = f"{maker_nick}!MyNick!sw0reloffer 0 1000 100000 500 0.001!tbond BOND_PROOF_BASE64"

    msg_data = {"type": MessageType.PRIVMSG.value, "line": offer_msg}

    # Mock receive to return the message then raise CancelledError to stop loop
    client.connection.receive.side_effect = [
        json.dumps(msg_data).encode("utf-8"),
        asyncio.CancelledError("Stop"),
    ]

    # Mock get_peerlist_with_features to do nothing
    client.get_peerlist_with_features = AsyncMock()

    # Mock parse_fidelity_bond_proof to verify arguments
    with patch("jmcore.directory_client.parse_fidelity_bond_proof") as mock_parse:
        # Pre-populate peer features
        client.peer_features = {maker_nick: {}}

        # Return a dummy bond dict so the code proceeds
        mock_parse.return_value = {
            "utxo_txid": "a" * 64,
            "utxo_vout": 0,
            "locktime": 1234567890,
            "utxo_pub": "02" + "a" * 64,
            "cert_expiry": 1000,
            "maker_nick": maker_nick,
            "taker_nick": "MyNick",
        }

        # Run listen_continuously for a short time
        with contextlib.suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(client.listen_continuously(request_orderbook=False), timeout=0.1)

        # Verify parse_fidelity_bond_proof was called with correct arguments
        # args: (proof_base64, maker_nick, taker_nick)
        # We expect taker_nick to be "MyNick" because it was a PRIVMSG to us
        mock_parse.assert_called_with("BOND_PROOF_BASE64", maker_nick, "MyNick")
