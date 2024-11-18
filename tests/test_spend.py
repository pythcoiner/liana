import math

from fixtures import *
from test_framework.serializations import PSBT, uint256_from_str
from test_framework.utils import (
    sign_and_broadcast_psbt,
    wait_for,
    COIN,
    RpcError,
    USE_TAPROOT,
)


def additional_fees(anc_vsize, anc_fee, target_feerate):
    """The additional fee which must have been computed by lianad."""
    computed_anc_vsize = int(anc_fee / target_feerate)
    extra_vsize = anc_vsize - computed_anc_vsize
    return extra_vsize * target_feerate


def test_spend_change(lianad, bitcoind):
    """We can spend a coin that was received on a change address."""
    # Receive a coin on a receive address
    addr = lianad.rpc.getnewaddress()["address"]
    txid = bitcoind.rpc.sendtoaddress(addr, 0.01)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 1)

    # Create a transaction that will spend this coin to 1) one of our receive
    # addresses 2) an external address 3) one of our change addresses.
    outpoints = [c["outpoint"] for c in lianad.rpc.listcoins()["coins"]]
    destinations = {
        bitcoind.rpc.getnewaddress(): 100_000,
        lianad.rpc.getnewaddress()["address"]: 100_000,
    }
    res = lianad.rpc.createspend(destinations, outpoints, 2)
    assert "psbt" in res

    # The transaction must contain a change output.
    spend_psbt = PSBT.from_base64(res["psbt"])
    assert spend_psbt.tx
    assert len(spend_psbt.o) == 3
    assert len(spend_psbt.tx.vout) == 3
    # Since the transaction contains a change output there is no warning.
    assert len(res["warnings"]) == 0

    # Sign and broadcast this first Spend transaction.
    signed_psbt = lianad.signer.sign_psbt(spend_psbt)
    lianad.rpc.updatespend(signed_psbt.to_base64())
    spend_txid = signed_psbt.tx.txid().hex()
    lianad.rpc.broadcastspend(spend_txid)
    bitcoind.generate_block(1, wait_for_mempool=spend_txid)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 3)

    # Now create a new transaction that spends the change output as well as
    # the output sent to the receive address.
    outpoints = [
        c["outpoint"]
        for c in lianad.rpc.listcoins()["coins"]
        if c["spend_info"] is None
    ]
    destinations = {
        bitcoind.rpc.getnewaddress(): 100_000,
    }
    res = lianad.rpc.createspend(destinations, outpoints, 2)
    spend_psbt = PSBT.from_base64(res["psbt"])
    assert len(spend_psbt.o) == 2
    assert len(res["warnings"]) == 0

    # We can sign and broadcast it.
    signed_psbt = lianad.signer.sign_psbt(spend_psbt)
    lianad.rpc.updatespend(signed_psbt.to_base64())
    spend_txid = signed_psbt.tx.txid().hex()
    lianad.rpc.broadcastspend(spend_txid)
    bitcoind.generate_block(1, wait_for_mempool=spend_txid)


def test_coin_marked_spent(lianad, bitcoind):
    """Test a spent coin is marked as such under various conditions."""
    # Receive a coin in a single transaction
    addr = lianad.rpc.getnewaddress()["address"]
    deposit_a = bitcoind.rpc.sendtoaddress(addr, 0.01)
    bitcoind.generate_block(1, wait_for_mempool=deposit_a)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 1)

    # Receive another coin on the same address
    deposit_b = bitcoind.rpc.sendtoaddress(addr, 0.02)
    bitcoind.generate_block(1, wait_for_mempool=deposit_b)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 2)

    # Receive three coins in a single deposit transaction
    destinations = {
        lianad.rpc.getnewaddress()["address"]: 0.03,
        lianad.rpc.getnewaddress()["address"]: 0.04,
        lianad.rpc.getnewaddress()["address"]: 0.05,
    }
    deposit_c = bitcoind.rpc.sendmany("", destinations)
    bitcoind.generate_block(1, wait_for_mempool=deposit_c)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 5)

    # Receive a coin in an unconfirmed deposit transaction
    addr = lianad.rpc.getnewaddress()["address"]
    deposit_d = bitcoind.rpc.sendtoaddress(addr, 0.06)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 5)

    def sign_and_broadcast(psbt):
        txid = psbt.tx.txid().hex()
        psbt = lianad.signer.sign_psbt(psbt)
        lianad.rpc.updatespend(psbt.to_base64())
        lianad.rpc.broadcastspend(txid)
        return txid

    # Spend the first coin with a change output
    outpoint = next(
        c["outpoint"]
        for c in lianad.rpc.listcoins()["coins"]
        if deposit_a in c["outpoint"]
    )
    destinations = {
        bitcoind.rpc.getnewaddress(): 500_000,
    }
    res = lianad.rpc.createspend(destinations, [outpoint], 6)
    psbt = PSBT.from_base64(res["psbt"])
    sign_and_broadcast(psbt)
    assert len(psbt.o) == 2
    assert len(res["warnings"]) == 0

    # Spend the second coin without a change output
    outpoint = next(
        c["outpoint"]
        for c in lianad.rpc.listcoins()["coins"]
        if deposit_b in c["outpoint"]
    )
    destinations = {
        bitcoind.rpc.getnewaddress(): int(0.02 * COIN) - 1_000,
    }
    res = lianad.rpc.createspend(destinations, [outpoint], 1)
    psbt = PSBT.from_base64(res["psbt"])
    sign_and_broadcast(psbt)
    change_amount = 858 if USE_TAPROOT else 839
    assert len(psbt.o) == 1
    assert len(res["warnings"]) == 1
    assert (
        res["warnings"][0]
        == "Dust UTXO. The minimal change output allowed by Liana is 5000 sats. "
        f"Instead of creating a change of {change_amount} sats, it was added to the "
        "transaction fee. Select a larger input to avoid this from happening."
    )

    # Spend the third coin to an address of ours, no change
    coins_c = [c for c in lianad.rpc.listcoins()["coins"] if deposit_c in c["outpoint"]]
    destinations = {
        lianad.rpc.getnewaddress()["address"]: int(0.03 * COIN) - 1_000,
    }
    outpoint_3 = [c["outpoint"] for c in coins_c if c["amount"] == 0.03 * COIN][0]
    res = lianad.rpc.createspend(destinations, [outpoint_3], 1)
    psbt = PSBT.from_base64(res["psbt"])
    sign_and_broadcast(psbt)
    change_amount = 846 if USE_TAPROOT else 827
    assert len(psbt.o) == 1
    assert len(res["warnings"]) == 1
    assert (
        res["warnings"][0]
        == "Dust UTXO. The minimal change output allowed by Liana is 5000 sats. "
        f"Instead of creating a change of {change_amount} sats, it was added to the "
        "transaction fee. Select a larger input to avoid this from happening."
    )

    # Spend the fourth coin to an address of ours, with change
    outpoint_4 = [c["outpoint"] for c in coins_c if c["amount"] == 0.04 * COIN][0]
    destinations = {
        lianad.rpc.getnewaddress()["address"]: int(0.04 * COIN / 2),
    }
    res = lianad.rpc.createspend(destinations, [outpoint_4], 18)
    psbt = PSBT.from_base64(res["psbt"])
    sign_and_broadcast(psbt)
    assert len(psbt.o) == 2
    assert len(res["warnings"]) == 0

    # Batch spend the fifth and sixth coins
    outpoint_5 = [c["outpoint"] for c in coins_c if c["amount"] == 0.05 * COIN][0]
    outpoint_6 = next(
        c["outpoint"]
        for c in lianad.rpc.listcoins()["coins"]
        if deposit_d in c["outpoint"]
    )
    destinations = {
        lianad.rpc.getnewaddress()["address"]: int(0.01 * COIN),
        lianad.rpc.getnewaddress()["address"]: int(0.01 * COIN),
        bitcoind.rpc.getnewaddress(): int(0.01 * COIN),
    }
    res = lianad.rpc.createspend(destinations, [outpoint_5, outpoint_6], 2)
    psbt = PSBT.from_base64(res["psbt"])
    sign_and_broadcast(psbt)
    assert len(psbt.o) == 4
    anc_vsize = bitcoind.rpc.getmempoolentry(deposit_d)["ancestorsize"]
    anc_fees = int(bitcoind.rpc.getmempoolentry(deposit_d)["fees"]["ancestor"] * COIN)
    additional_fee = additional_fees(anc_vsize, anc_fees, 2)
    assert len(res["warnings"]) == 1
    assert (
        res["warnings"][0]
        == "CPFP: an unconfirmed input was selected. The current transaction fee "
        f"was increased by {additional_fee} sats to make the average feerate of "
        "both the input and current transaction equal to the selected feerate."
    )

    # All the spent coins must have been detected as such
    all_deposits = (deposit_a, deposit_b, deposit_c, deposit_d)

    def deposited_coins():
        return (
            c
            for c in lianad.rpc.listcoins()["coins"]
            if c["outpoint"][:-2] in all_deposits
        )

    def is_spent(coin):
        if coin["spend_info"] is None:
            return False
        if coin["spend_info"]["txid"] is None:
            return False
        return True

    wait_for(lambda: all(is_spent(c) for c in deposited_coins()))


def test_send_to_self(lianad, bitcoind):
    """Test we can use createspend with no destination to send to a change address."""
    # Get 3 coins.
    destinations = {
        lianad.rpc.getnewaddress()["address"]: 0.03,
        lianad.rpc.getnewaddress()["address"]: 0.04,
        lianad.rpc.getnewaddress()["address"]: 0.05,
    }
    deposit_txid = bitcoind.rpc.sendmany("", destinations)
    bitcoind.generate_block(1, wait_for_mempool=deposit_txid)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 3)

    # Then create a send-to-self transaction (by not providing any destination) that
    # sweeps them all.
    outpoints = [c["outpoint"] for c in lianad.rpc.listcoins()["coins"]]
    specified_feerate = 142
    res = lianad.rpc.createspend({}, outpoints, specified_feerate)
    spend_psbt = PSBT.from_base64(res["psbt"])
    assert spend_psbt.tx
    assert len(spend_psbt.o) == len(spend_psbt.tx.vout) == 1

    # Note they may ask for an impossible send-to-self. In this case we'll report missing amount.
    huge_feerate = 50_000 if USE_TAPROOT else 40_500
    assert "missing" in lianad.rpc.createspend({}, outpoints, huge_feerate)

    # Sign and broadcast the send-to-self transaction created above.
    signed_psbt = lianad.signer.sign_psbt(spend_psbt)
    lianad.rpc.updatespend(signed_psbt.to_base64())
    spend_txid = signed_psbt.tx.txid().hex()
    lianad.rpc.broadcastspend(spend_txid)

    # The only output is the change output so the feerate of the transaction must
    # not be much lower than the one provided (it could be slightly lower since
    # the change amount is determined using feerate in terms of sat/wu which, due
    # to rounding, can lead to a slightly lower feerate in terms of sat/vb,
    # especially when the number of inputs increases), and only possibly slightly
    # higher (since we slightly overestimate the satisfaction size).
    res = bitcoind.rpc.getmempoolentry(spend_txid)
    spend_feerate = res["fees"]["base"] * COIN / res["vsize"]  # keep as decimal
    if USE_TAPROOT:
        assert specified_feerate <= spend_feerate < specified_feerate + 0.5
    else:
        assert specified_feerate - 0.5 < spend_feerate < specified_feerate + 0.5

    # We should by now only have one coin.
    bitcoind.generate_block(1, wait_for_mempool=spend_txid)
    unspent_coins = lambda: (
        c for c in lianad.rpc.listcoins()["coins"] if c["spend_info"] is None
    )
    wait_for(lambda: len(list(unspent_coins())) == 1)

    # We've used 3 receive addresses and so the DB receive index must be 3.
    assert len(lianad.rpc.listaddresses()["addresses"]) == 3
    # Create a new spend to the receive address with index 3.
    recv_addr = lianad.rpc.listaddresses(3, 1)["addresses"][0]["receive"]
    res = lianad.rpc.createspend(
        {recv_addr: 11_965_000 if USE_TAPROOT else 11_955_000}, [], 2
    )
    assert "psbt" in res
    # Max(receive_index, change_index) is now 4:
    assert len(lianad.rpc.listaddresses()["addresses"]) == 4
    # But the spend has no change:
    psbt = PSBT.from_base64(res["psbt"])
    assert len(psbt.o) == 1
    # As the spend has no change, only the receive index was incremented.
    # Therefore, the DB receive index is now 4.


def test_coin_selection(lianad, bitcoind):
    """We can create a spend using coin selection."""
    # Send to an (external) address.
    dest_addr_1 = bitcoind.rpc.getnewaddress()
    # Coin selection is not possible if we have no coins.
    assert len(lianad.rpc.listcoins()["coins"]) == 0
    assert "missing" in lianad.rpc.createspend({dest_addr_1: 100_000}, [], 2)

    # Receive a coin in an unconfirmed deposit transaction.
    recv_addr_1 = lianad.rpc.getnewaddress()["address"]
    deposit_1 = bitcoind.rpc.sendtoaddress(recv_addr_1, 0.0012)  # 120_000 sats
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 1)
    # There are still no confirmed coins or unconfirmed change
    # to use as candidates for selection.
    assert len(lianad.rpc.listcoins(["confirmed"])["coins"]) == 0
    assert len(lianad.rpc.listcoins(["unconfirmed"])["coins"]) == 1
    assert lianad.rpc.listcoins(["unconfirmed"])["coins"][0]["is_change"] is False
    assert "missing" in lianad.rpc.createspend({dest_addr_1: 100_000}, [], 2)

    # Confirm coin.
    bitcoind.generate_block(1, wait_for_mempool=deposit_1)
    wait_for(lambda: len(lianad.rpc.listcoins(["confirmed"])["coins"]) == 1)
    # Coin selection now succeeds.
    spend_res_1 = lianad.rpc.createspend({dest_addr_1: 100_000}, [], 2)
    assert "psbt" in spend_res_1
    assert len(spend_res_1["warnings"]) == 0
    # Increase spend amount and we have insufficient funds again even though we
    # now have confirmed coins.
    assert "missing" in lianad.rpc.createspend({dest_addr_1: 200_000}, [], 2)

    # The transaction contains a change output.
    spend_psbt_1 = PSBT.from_base64(spend_res_1["psbt"])
    assert spend_psbt_1.tx
    assert len(spend_psbt_1.o) == 2
    assert len(spend_psbt_1.tx.vout) == 2

    # Sign and broadcast this Spend transaction.
    spend_txid_1 = sign_and_broadcast_psbt(lianad, spend_psbt_1)
    # Check its feerate is approx 2 sat/vb
    anc_vsize = bitcoind.rpc.getmempoolentry(spend_txid_1)["ancestorsize"]
    anc_fees = int(
        bitcoind.rpc.getmempoolentry(spend_txid_1)["fees"]["ancestor"] * COIN
    )
    # txid_1's feerate is approx 2 sat/vb as required.
    txid_1_feerate = anc_fees / anc_vsize
    assert 1.99 < txid_1_feerate < 2.01
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 2)
    # Check that change output is unconfirmed.
    assert len(lianad.rpc.listcoins(["unconfirmed"])["coins"]) == 1
    assert lianad.rpc.listcoins(["unconfirmed"])["coins"][0]["is_change"] is True
    assert len(lianad.rpc.listcoins(["spending"])["coins"]) == 1
    # We can use unconfirmed change as candidate.
    # Depending on the feerate, we'll get a warning about paying extra for the ancestor.
    dest_addr_2 = bitcoind.rpc.getnewaddress()
    # If feerate is higher than ancestor, we'll need to pay extra.

    # Try 10 sat/vb:
    feerate = 10
    spend_res_2 = lianad.rpc.createspend({dest_addr_2: 10_000}, [], feerate)
    assert "psbt" in spend_res_2
    spend_psbt_2 = PSBT.from_base64(spend_res_2["psbt"])
    assert spend_psbt_2.tx
    # The spend is using the unconfirmed change.
    assert spend_psbt_2.tx.vin[0].prevout.hash == uint256_from_str(
        bytes.fromhex(spend_txid_1)[::-1]
    )
    additional_fee_at_10satvb = additional_fees(anc_vsize, anc_fees, feerate)
    assert len(spend_res_2["warnings"]) == 1
    assert (
        spend_res_2["warnings"][0]
        == "CPFP: an unconfirmed input was selected. The current transaction fee "
        f"was increased by {additional_fee_at_10satvb} sats to make the average "
        "feerate of both the input and current transaction equal to the selected "
        "feerate."
    )

    # Try 3 sat/vb:
    feerate = 3
    spend_res_2 = lianad.rpc.createspend({dest_addr_2: 10_000}, [], feerate)
    assert "psbt" in spend_res_2
    spend_psbt_2 = PSBT.from_base64(spend_res_2["psbt"])
    assert spend_psbt_2.tx
    # The spend is using the unconfirmed change.
    assert spend_psbt_2.tx.vin[0].prevout.hash == uint256_from_str(
        bytes.fromhex(spend_txid_1)[::-1]
    )
    additional_fee_at_3satvb = additional_fees(anc_vsize, anc_fees, feerate)
    assert additional_fee_at_10satvb > additional_fee_at_3satvb
    assert len(spend_res_2["warnings"]) == 1
    assert (
        spend_res_2["warnings"][0]
        == "CPFP: an unconfirmed input was selected. The current transaction fee "
        f"was increased by {additional_fee_at_3satvb} sats to make the average "
        "feerate of both the input and current transaction equal to the selected "
        "feerate."
    )

    # 2 sat/vb is approx same feerate as ancestor:
    feerate = 2
    spend_res_2 = lianad.rpc.createspend({dest_addr_2: 10_000}, [], feerate)
    assert "psbt" in spend_res_2
    spend_psbt_2 = PSBT.from_base64(spend_res_2["psbt"])
    assert spend_psbt_2.tx
    spend_txid_2 = spend_psbt_2.tx.txid().hex()
    if USE_TAPROOT:
        assert len(spend_res_2["warnings"]) == 0
    else:
        # We still get a warning in the non-taproot case.
        assert len(spend_res_2["warnings"]) == 1
        additional_fee_at_2satvb = additional_fees(anc_vsize, anc_fees, feerate)
        assert additional_fee_at_3satvb > additional_fee_at_2satvb
        assert len(spend_res_2["warnings"]) == 1
        assert (
            spend_res_2["warnings"][0]
            == "CPFP: an unconfirmed input was selected. The current transaction fee "
            f"was increased by {additional_fee_at_2satvb} sats to make the average "
            "feerate of both the input and current transaction equal to the selected "
            "feerate."
        )

    # The spend is using the unconfirmed change.
    assert spend_psbt_2.tx.vin[0].prevout.hash == uint256_from_str(
        bytes.fromhex(spend_txid_1)[::-1]
    )

    # Get another coin to check coin selection with more than one candidate.
    recv_addr_2 = lianad.rpc.getnewaddress()["address"]
    deposit_2 = bitcoind.rpc.sendtoaddress(recv_addr_2, 30_000 / COIN)
    wait_for(lambda: len(lianad.rpc.listcoins(["unconfirmed"])["coins"]) == 2)
    assert (
        len(
            [
                c
                for c in lianad.rpc.listcoins(["unconfirmed"])["coins"]
                if c["is_change"]
            ]
        )
        == 1
    )
    dest_addr_3 = bitcoind.rpc.getnewaddress()
    # As only one unconfirmed coin is change, we have insufficient funds.
    assert "missing" in lianad.rpc.createspend({dest_addr_3: 20_000}, [], 10)

    # If we include both unconfirmed coins manually, it will succeed.
    # We'll need to pay extra for each unconfirmed coin's ancestors.
    outpoints = [c["outpoint"] for c in lianad.rpc.listcoins(["unconfirmed"])["coins"]]

    feerate = 10
    spend_res_3 = lianad.rpc.createspend({dest_addr_3: 20_000}, outpoints, feerate)
    assert "psbt" in spend_res_3
    anc_vsize = bitcoind.rpc.getmempoolentry(deposit_2)["ancestorsize"]
    anc_fees = int(bitcoind.rpc.getmempoolentry(deposit_2)["fees"]["ancestor"] * COIN)
    prev_anc_vsize = bitcoind.rpc.getmempoolentry(spend_txid_1)["ancestorsize"]
    prev_anc_fees = int(
        bitcoind.rpc.getmempoolentry(spend_txid_1)["fees"]["ancestor"] * COIN
    )
    additional_fee = additional_fees(anc_vsize, anc_fees, feerate) + additional_fees(
        prev_anc_vsize, prev_anc_fees, feerate
    )
    assert len(spend_res_3["warnings"]) == 1
    assert (
        spend_res_3["warnings"][0]
        == "CPFP: an unconfirmed input was selected. The current transaction fee "
        f"was increased by {additional_fee} sats to make the average feerate of "
        "both the input and current transaction equal to the selected feerate."
    )
    spend_psbt_3 = PSBT.from_base64(spend_res_3["psbt"])
    spend_txid_3 = sign_and_broadcast_psbt(lianad, spend_psbt_3)
    mempool_txid_3 = bitcoind.rpc.getmempoolentry(spend_txid_3)
    # The effective feerate of new transaction plus ancestor matches the target.
    # Note that in the mempool entry, "ancestor" includes spend_txid_3 itself.
    assert (
        mempool_txid_3["fees"]["ancestor"] * COIN // mempool_txid_3["ancestorsize"]
        == feerate
    )
    # The spend_txid_3 transaction itself has a higher feerate.
    assert (mempool_txid_3["fees"]["base"] * COIN) // mempool_txid_3["vsize"] > 10
    # If we subtract the extra that pays for the ancestor, the feerate is approximately
    # at the target value.
    assert (
        feerate - 0.5
        < ((mempool_txid_3["fees"]["base"] * COIN) - additional_fee)
        / mempool_txid_3["vsize"]
        < feerate + 0.5
    )

    # Now confirm the spend.
    bitcoind.generate_block(1, wait_for_mempool=spend_txid_3)
    wait_for(lambda: len(lianad.rpc.listcoins(["confirmed"])["coins"]) == 1)

    # Now create the same spend with auto and manual selection:
    dest_addr_4 = bitcoind.rpc.getnewaddress()
    spend_res_4 = lianad.rpc.createspend({dest_addr_4: 15_000}, [], 2)
    assert "psbt" in spend_res_4
    assert len(spend_res_4["warnings"]) == 0

    # The transaction contains a change output.
    spend_psbt_4 = PSBT.from_base64(spend_res_4["psbt"])
    assert spend_psbt_4.tx
    assert len(spend_psbt_4.i) == 1
    assert len(spend_psbt_4.o) == 2
    assert len(spend_psbt_4.tx.vout) == 2

    # Now create a transaction with manual coin selection using the same outpoints.
    outpoints = [
        f"{txin.prevout.hash:064x}:{txin.prevout.n}" for txin in spend_psbt_4.tx.vin
    ]
    assert len(outpoints) > 0
    res_manual = lianad.rpc.createspend({dest_addr_4: 15_000}, outpoints, 2)
    assert len(res_manual["warnings"]) == 0
    psbt_manual = PSBT.from_base64(res_manual["psbt"])
    assert psbt_manual.tx

    # Recipient details are the same for both.
    assert spend_psbt_4.tx.vout[0].nValue == psbt_manual.tx.vout[0].nValue
    assert spend_psbt_4.tx.vout[0].scriptPubKey == psbt_manual.tx.vout[0].scriptPubKey
    # Change amount is the same (change address will be different).
    assert spend_psbt_4.tx.vout[1].nValue == psbt_manual.tx.vout[1].nValue
    assert spend_psbt_4.tx.vout[1].scriptPubKey != psbt_manual.tx.vout[1].scriptPubKey


def test_coin_selection_changeless(lianad, bitcoind):
    """We choose the changeless solution with lowest fee."""
    # Get two coins with similar amounts.
    txid_a = bitcoind.rpc.sendtoaddress(lianad.rpc.getnewaddress()["address"], 0.00031)
    txid_b = bitcoind.rpc.sendtoaddress(lianad.rpc.getnewaddress()["address"], 0.00032)
    bitcoind.generate_block(1, wait_for_mempool=[txid_a, txid_b])
    wait_for(lambda: len(lianad.rpc.listcoins(["confirmed"])["coins"]) == 2)
    # Send an amount that can be paid by just one of our coins.
    res = lianad.rpc.createspend({bitcoind.rpc.getnewaddress(): 30800}, [], 1)
    psbt = PSBT.from_base64(res["psbt"])
    assert psbt.tx
    # Only one input needed.
    assert len(psbt.i) == 1
    # Coin A is used as input.
    txid_a = uint256_from_str(bytes.fromhex(txid_a)[::-1])
    assert psbt.tx.vin[0].prevout.hash == txid_a


def test_sweep(lianad, bitcoind):
    """
    Test we can leverage the change_address parameter to partially or completely sweep
    the wallet's coins.
    """

    # Get a bunch of coins. Don't even confirm them.
    destinations = {
        lianad.rpc.getnewaddress()["address"]: 0.8,
        lianad.rpc.getnewaddress()["address"]: 0.12,
        lianad.rpc.getnewaddress()["address"]: 1.87634,
        lianad.rpc.getnewaddress()["address"]: 1.124,
    }
    bitcoind.rpc.sendmany("", destinations)
    wait_for(lambda: len(lianad.rpc.listcoins()["coins"]) == 4)

    # Create a sweep transaction. This should send the whole balance to the
    # sweep address.
    all_coins = lianad.rpc.listcoins()["coins"]
    balance = sum(c["amount"] for c in all_coins)
    all_outpoints = [c["outpoint"] for c in all_coins]
    destinations = {}
    change_addr = bitcoind.rpc.getnewaddress()
    res = lianad.rpc.createspend(destinations, all_outpoints, 1, change_addr)
    psbt = PSBT.from_base64(res["psbt"])
    assert psbt.tx
    assert len(psbt.tx.vout) == 1
    assert psbt.tx.vout[0].nValue > balance - 500
    sign_and_broadcast_psbt(lianad, psbt)
    wait_for(
        lambda: all(
            c["spend_info"] is not None for c in lianad.rpc.listcoins()["coins"]
        )
    )

    # Create a partial sweep and specify some destinations to be set before the
    # sweep output. To make it even more confusing, set one such destination as
    # an internal (but receive) address.
    destinations = {
        lianad.rpc.getnewaddress()["address"]: 0.5,
        lianad.rpc.getnewaddress()["address"]: 0.2,
        lianad.rpc.getnewaddress()["address"]: 0.1,
    }
    txid = bitcoind.rpc.sendmany("", destinations)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: len(lianad.rpc.listcoins(["confirmed"])["coins"]) == 3)
    received_coins = lianad.rpc.listcoins(["confirmed"])["coins"]
    spent_coin = next(c for c in received_coins if c["amount"] == 0.5 * COIN)
    destinations = {
        "bcrt1qmm5t0ch7vh2hryx9ctq3mswexcugqe4atkpkl2tetm8merqkthas3w7q30": int(
            0.1 * COIN
        ),
        lianad.rpc.getnewaddress()["address"]: int(0.3 * COIN),
    }
    res = lianad.rpc.createspend(destinations, [spent_coin["outpoint"]], 1, change_addr)
    psbt = PSBT.from_base64(res["psbt"])
    assert psbt.tx
    assert len(psbt.tx.vout) == 3
    sign_and_broadcast_psbt(lianad, psbt)
    wait_for(lambda: len(lianad.rpc.listcoins(["unconfirmed"])["coins"]) == 1)
    wait_for(lambda: len(lianad.rpc.listcoins(["confirmed"])["coins"]) == 2)
    balance = sum(
        c["amount"] for c in lianad.rpc.listcoins(["unconfirmed", "confirmed"])["coins"]
    )
    assert balance == int((0.2 + 0.1 + 0.3) * COIN)


@pytest.mark.parametrize("feerate", [1, 2])
@pytest.mark.skipif(not USE_TAPROOT, reason="This tests a Taproot-specific bug.")
def test_tr_multisig_2_of_2_feerate_is_met(feerate, lianad_multisig_2_of_2, bitcoind):
    """
    A regression test for https://github.com/wizardsardine/liana/issues/1371.

    Test that a 2-of-2 Taproot primary path spend pays a high enough fee for
    the target feerate.

    See https://mempool.space/signet/tx/a63c4a69be71fcba0e16f742a2697401fbc47ad7dff10a790b8f961004aa0ab4
    for an example of such a transaction.
    """
    # Get a coin.
    deposit_txid = bitcoind.rpc.sendtoaddress(
        lianad_multisig_2_of_2.rpc.getnewaddress()["address"], 0.001
    )
    bitcoind.generate_block(1, wait_for_mempool=deposit_txid)
    wait_for(
        lambda: len(lianad_multisig_2_of_2.rpc.listcoins(["confirmed"])["coins"]) == 1
    )
    coin = lianad_multisig_2_of_2.rpc.listcoins(["confirmed"])["coins"][0]

    # Refresh the coin at the given feerate.
    res = lianad_multisig_2_of_2.rpc.createspend({}, [coin["outpoint"]], feerate)
    spend_psbt = PSBT.from_base64(res["psbt"])
    signed_psbt = lianad_multisig_2_of_2.signer.sign_psbt(spend_psbt, [0, 1])
    lianad_multisig_2_of_2.rpc.updatespend(signed_psbt.to_base64())
    spend_txid = signed_psbt.tx.txid().hex()
    lianad_multisig_2_of_2.rpc.broadcastspend(spend_txid)

    # Check the tx fee and weight in mempool are as expected.
    res = bitcoind.rpc.getmempoolentry(spend_txid)
    spend_fee = res["fees"]["base"] * COIN
    spend_weight = res["weight"]
    assert spend_weight == 646

    # Note that due to https://github.com/wizardsardine/liana/issues/1132
    # we do not round up vbytes before multiplying by feerate.
    assert spend_fee == math.ceil((646.0 / 4.0) * feerate)
