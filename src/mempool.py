import copy
import sqlite3

import constants as const
import objects
import json

def expand_object(obj_str):
    return json.loads(obj_str)

# get expanded object for 
def fetch_object(oid, cur):
    res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (oid,))
    row = res.fetchone()
    if row is not None:
        return expand_object(row[0])
    else:
        return None

# get utxo for block and normalize keys to int
def fetch_utxo(bid, cur):
    res = cur.execute("SELECT utxoset FROM utxo WHERE blockid = ?", (bid,))
    row = res.fetchone()
    if row is not None:
        utxo_json = json.loads(row[0])
        # normalize keys to int
        utxo_fixed = {}
        for txid, outs in utxo_json.items():
            utxo_fixed[txid] = {int(idx): value for idx, value in outs.items()}
        return utxo_fixed
    else:
        return None

# returns (blockid, intermediate_blocks)
def find_lca_and_intermediate_blocks(tipid, blockids):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        intermediate_blocks = []
        pointer = fetch_object(tipid, cur)
        pointerid = tipid
        while pointer:
            if pointerid in blockids:
                return (pointerid, intermediate_blocks)
            intermediate_blocks.append(pointer)
            if pointer['previd'] is None:
                return (pointerid, intermediate_blocks)
            pointer = fetch_object(pointer['previd'], cur)
            pointerid = objects.get_objid(pointer)
    finally:
        con.close()


# return a list of transactions by index
def find_all_txs(txids):
    txs = []
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        for txid in txids:
            txs.append(fetch_object(txid, cur))
    finally:
        con.close()
    return txs

# return a list of transactions in blocks
def get_all_txids_in_blocks(blocks):
    txids = []
    for block in blocks:
        for txid in block['txids']:
            txids.append(txid)
    return txids

# get (id of lca, list of old blocks from lca, list of new blocks from lca) 
def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # collect all blocks of the old chain
        old_blocks = []
        pointer = fetch_object(old_tip, cur)
        old_chain_ids = []
        while pointer:
            old_chain_ids.append(objects.get_objid(pointer))
            old_blocks.append(pointer)
            if pointer['previd'] is None:
                break
            pointer = fetch_object(pointer['previd'], cur)
        old_blocks.reverse()  # from LCA -> tip

        # New chain: find LCA and intermediates using helper function
        result = find_lca_and_intermediate_blocks(
            new_tip,
            old_chain_ids
        )
        lca_id, new_blocks_from_lca = result
        #lca_id, new_blocks_from_lca = find_lca_and_intermediate_blocks(
        #    new_tip,
        #    old_chain_ids
        #)

        # Extract old blocks from LCA
        old_blocks_from_lca = []
        lca_found = False
        for b in old_blocks:
            if objects.get_objid(b) == lca_id:
                lca_found = True
                continue
            if lca_found:
                old_blocks_from_lca.append(b)

        return (lca_id, old_blocks_from_lca, new_blocks_from_lca)

    finally:
        con.close()


def rebase_mempool(old_tip, new_tip, mptxids):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        print("REBASE MEMPOOL FROM", old_tip, "TO", new_tip)

        # LCA + old/new Blocks
        lca_id, old_blocks, new_blocks = get_lca_and_intermediate_blocks(old_tip, new_tip)

        # UTXO on LCA
        utxo = fetch_utxo(lca_id, cur) or {}
        utxo = copy.deepcopy(utxo)

        print("LCA:", lca_id)
        print("Fetching UTXO for:", lca_id)
        print("UTXO:", utxo)

        # helper function: applies a TX (including coinbase) to a utxo dict
        def apply_tx_to_utxo(tx, utxo_dict):
            for inp in tx.get("inputs", []):
                op = inp["outpoint"]
                in_txid = op["txid"]
                idx = op["index"]
                if in_txid not in utxo_dict or idx not in utxo_dict[in_txid]:
                    return False
            for inp in tx.get("inputs", []):
                op = inp["outpoint"]
                in_txid = op["txid"]
                idx = op["index"]
                del utxo_dict[in_txid][idx]
                if not utxo_dict[in_txid]:
                    del utxo_dict[in_txid]
            txid = objects.get_objid(tx)
            utxo_dict[txid] = {}
            for i, out in enumerate(tx.get("outputs", [])):
                utxo_dict[txid][i] = out["value"]
            return True

        # apply new chain blocks 
        for block in new_blocks:
            txids = get_all_txids_in_blocks([block])
            txs = find_all_txs(txids)

            tmp_utxo = copy.deepcopy(utxo)
            valid_block = True
            for tx in txs:
                if not apply_tx_to_utxo(tx, tmp_utxo):
                    valid_block = False
                    break

            if valid_block:
                utxo = tmp_utxo
            else:
                print("Invalid block encountered during rebase, discarding following new blocks")
                break

        # prepare set of txids that are now included in the new chain (so we can skip them)
        included_txids = set(get_all_txids_in_blocks(new_blocks))

        # try to use txs from old blocks first
        new_mempool = Mempool(new_tip, copy.deepcopy(utxo))

        old_block_txids = get_all_txids_in_blocks(old_blocks)  # order preserved LCA->tip
        if old_block_txids:
            old_block_txs = find_all_txs(old_block_txids)
            for tx in old_block_txs:
                txid = objects.get_objid(tx)

                # if tx in new chain already, skip
                if txid in included_txids:
                    print(f"SKIP OLD-BLOCK TX {txid}: now included in new chain")
                    continue

                # check that all inputs are still unspent
                input_conflict = False
                for inp in tx.get("inputs", []):
                    op = inp["outpoint"]
                    in_txid = op["txid"]
                    idx = op["index"]
                    if in_txid not in utxo or idx not in utxo[in_txid]:
                        input_conflict = True
                        break
                if input_conflict:
                    print(f"DROP OLD-BLOCK TX {txid}: inputs missing/spent against new chain")
                    continue

                # try to add to mempool (this will detect conflicts with other mempool TXs)
                added = new_mempool.try_add_tx(tx)
                if not added:
                    print(f"REJECT OLD-BLOCK TX {txid}: conflict with mempool state")

        # try old mempool txs next
        old_txs = find_all_txs(mptxids)
        for tx in old_txs:
            txid = objects.get_objid(tx)

            # Skip if the tx is included in the new chain already
            if txid in included_txids:
                print(f"SKIP Mempool TX {txid}: already included in new chain")
                continue

            # Pre-check against chain-utxo (after applying new chain)
            input_conflict = False
            for inp in tx.get("inputs", []):
                op = inp["outpoint"]
                in_txid = op["txid"]
                idx = op["index"]
                if in_txid not in utxo or idx not in utxo[in_txid]:
                    input_conflict = True
                    break
            if input_conflict:
                print(f"REJECT Mempool TX {txid}: input already spent in chain or missing")
                continue

            added = new_mempool.try_add_tx(tx)
            if not added:
                print(f"REJECT Mempool TX {txid}: failed to add to mempool (conflict)")

        print("THE NEW MEMPOOL UTXO IS:", new_mempool.utxo)
        print("NEW MEMPOOL STATE:", new_mempool.txs, new_mempool.utxo)
        return (new_tip, new_mempool.utxo, new_mempool.txs)

    finally:
        con.close()



class Mempool:
    def __init__(self, bbid: str, butxo: dict):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []

    def try_add_tx(self, tx: dict) -> bool:
        txid = objects.get_objid(tx)

        # Check if coinbase tx
        if 'height' in tx:
            print("REJECTING COINBASE TX")
            return False

        print("THIS IS CALLED WITH TXID:", txid)
        print("THIS IS THE TX:", tx)
        print("THIS IS MY CURRENT UTXO:", self.utxo)

        # Check inputs
        for inp in tx["inputs"]:
            op = inp["outpoint"]
            in_txid = op["txid"]
            idx = op["index"]

            if in_txid not in self.utxo:
                print("REJECTING NOT IN UTXO")
                return False
            if idx not in self.utxo[in_txid]:
                print("REJECTING NOT IN UTXO")
                return False

        # Execute them
        for inp in tx["inputs"]:
            op = inp["outpoint"]
            in_txid = op["txid"]
            idx = op["index"]

            del self.utxo[in_txid][idx]
            if not self.utxo[in_txid]:
                del self.utxo[in_txid]

        # Add outputs
        self.utxo[txid] = {}
        for i, out in enumerate(tx["outputs"]):
            self.utxo[txid][i] = out["value"]

        # Add tx to mempool
        self.txs.append(txid)
        return True

    def rebase_to_block(self, bid: str):
        old_mptxids = self.txs.copy()

        # rebase mempool
        new_base, new_utxo, new_mptxids = rebase_mempool(
            self.base_block_id,
            bid,
            old_mptxids
        )

        self.base_block_id = new_base
        self.utxo = new_utxo
        self.txs = new_mptxids
        print("NEW MEMPOOL STATE:", self.txs, self.utxo)