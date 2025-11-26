.PHONY: docker-build docker-up run build clean make-submission check-submission remove-submission remove-test

run:
	cd src && python3 main.py

clean: remove-submission remove-test
	# add further actions if needed
	rm -f src/db.db
	rm -f src/peers.json
	rm -rf src/__pycache__
	rm -rf src/message/__pycache__

build:
	pip3 install --no-cache-dir -r src/requirements.txt

# add own tests if you want

# weird, the ids seem to have changed?
# i wrote in the discussion forum
#GENESIS_ID := 0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2
GENESIS_ID := 00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee

run-tests:
	make test_valid_block_from_spec
	make test_block_incorrect_target
	make test_block_invalid_pow
	make test_block_invalid_transaction_in_block
	make test_block_utxo_not_exists
	make test_block_missing_parent
	make test_block_with_unknown_tx
	make test_block_coinbase_with_inputs
	make test_block_invalid_format

# Test: Example valid block from spec must be accepted and gossiped
# Läuft auf der lecute node nur mit not gossiped - wahrschienlich weil das object dort schon ist.
test_valid_block_from_spec:
	@echo "== test_valid_block_from_spec =="
	@{ \
	  mkfifo /tmp/grader2_spec_block 2>/dev/null || true; \
	  { \
	    printf '{"agent":"grader2","type":"hello","version":"0.10.0"}\n'; \
	    sleep 10; \
	  } | nc -v -w 15 localhost 18018 > /tmp/grader2_spec_block.out & \
	  GRADER2_PID=$$!; \
	  sleep 1; \
	  { \
	    printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	    sleep 0.2; \
	    printf '{"type":"object","object":{"height":1,"outputs":[{"pubkey":"3f0bc71a375b574e4bda3ddf502fe1afd99aa020bf6049adfe525d9ad18ff33f","value":50000000000000}],"type":"transaction"}}\n'; \
	    sleep 0.3; \
	    printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":1671148800,"miner":"grader","nonce":"00000000000000000000000000000000000000000000000000000000000463cf","note":"This block has a coinbase transaction","previd":"$(GENESIS_ID)","txids":["6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"],"type":"block"}}\n'; \
	    sleep 2; \
	  } | nc -v -w 5 localhost 18018 > /tmp/grader1_spec_block.out; \
	  sleep 1; \
	  kill $$GRADER2_PID 2>/dev/null || true; \
	  if grep -q '"type":"error"' /tmp/grader1_spec_block.out; then \
	    echo "✗ Example valid block rejected"; \
	    cat /tmp/grader1_spec_block.out; \
	    rm -f /tmp/grader1_spec_block.out /tmp/grader2_spec_block.out /tmp/grader2_spec_block; \
	    exit 1; \
	  fi; \
	  if grep -q '"type":"ihaveobject"' /tmp/grader2_spec_block.out && grep -q '000020cb0002575a71955763adf365c78182f0bb5bee767794ebc7346e0a2194' /tmp/grader2_spec_block.out; then \
	    echo "✓ Example valid block accepted and gossiped"; \
	    cat /tmp/grader2_spec_block.out; \
	    rm -f /tmp/grader1_spec_block.out /tmp/grader2_spec_block.out /tmp/grader2_spec_block; \
	    exit 0; \
	  else \
	    echo "✗ Example valid block not gossiped"; \
	    cat /tmp/grader1_spec_block.out; \
	    rm -f /tmp/grader1_spec_block.out /tmp/grader2_spec_block.out /tmp/grader2_spec_block; \
	    exit 1; \
	  fi; \
	}

## Lauft auf der lecture node
test_tx_error_specific:
	@echo "== test_tx_error_specific =="
	@{ \
	  printf '{"agent":"tx-tester","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"type":"transaction","height":0}}\n'; \
	  sleep 0.5; \
	} | nc -v -w 5 localhost 18018 > /tmp/tx_error_specific.out
	@if grep -q '"type":"error"' /tmp/tx_error_specific.out; then \
	  if grep -q 'JSON parse error' /tmp/tx_error_specific.out; then \
	    echo "✗ Only got JSON parse error (server still choking on input)"; \
	    cat /tmp/tx_error_specific.out; \
	    rm -f /tmp/tx_error_specific.out; \
	    exit 1; \
	  else \
	    echo "✓ Got a specific validation error (not just JSON parse error)"; \
	    cat /tmp/tx_error_specific.out; \
	    rm -f /tmp/tx_error_specific.out; \
	  fi; \
	else \
	  echo "✗ Did not get any error back"; \
	  cat /tmp/tx_error_specific.out; \
	  rm -f /tmp/tx_error_specific.out; \
	  exit 1; \
	fi


# Test: Invalid transaction (no outputs) must be rejected on its own
# läuft auf der lecture node
test_invalid_transaction_alone:
	@echo "== test_invalid_transaction_alone =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  INVALID_TX='{"height":'"$$TIMESTAMP"',"type":"transaction"}'; \
	  printf '{"type":"object","object":'"$$INVALID_TX"'}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_invalid_tx_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_invalid_tx_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  echo "✓ Invalid transaction rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Invalid transaction not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test: Block containing an invalid transaction must be rejected
test_block_invalid_transaction_in_block:
	@echo "== test_block_invalid_transaction_in_block =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  INVALID_TX='{"height":'"$$TIMESTAMP"',"type":"transaction"}'; \
	  INVALID_TXID=$$(echo "$$INVALID_TX" | jq -Sc | sha256sum | cut -d" " -f1); \
	  printf '{"type":"object","object":'"$$INVALID_TX"'}\n'; \
	  sleep 0.3; \
	  printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":'"$$TIMESTAMP"',"miner":"grader","nonce":"0000000000000000000000000000000000000000000000000000000000000001","previd":"$(GENESIS_ID)","txids":["'"$$INVALID_TXID"'"],"type":"block"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_invalid_tx_in_block_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_invalid_tx_in_block_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  echo "✓ Block with invalid transaction rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Block with invalid transaction not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 2: Block with incorrect target should be rejected
# lauft auf lecture node
test_block_incorrect_target:
	@echo "== test_block_incorrect_target =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-target" | sha256sum | cut -c1-64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  COINBASE_TX='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(echo "$$COINBASE_TX" | jq -Sc | sha256sum | cut -d" " -f1); \
	  printf '{"type":"object","object":'"$$COINBASE_TX"'}\n'; \
	  sleep 0.5; \
	  printf '{"type":"object","object":{"T":"0000fff000000000000000000000000000000000000000000000000000000000","created":'"$$TIMESTAMP"',"miner":"grader","nonce":"000000000000000000000000000000000000000000000000000000000004e315","previd":"$(GENESIS_ID)","txids":["'"$$COINBASE_TXID"'"],"type":"block"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_target_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_target_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  echo "✓ Block with incorrect target rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Block with incorrect target not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 3: Block with invalid proof-of-work should be rejected
# dieser Test läuft auf der lecture node.
test_block_invalid_pow:
	@echo "== test_block_invalid_pow =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-pow" | sha256sum | cut -c1-64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  COINBASE_TX='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(echo "$$COINBASE_TX" | jq -Sc | sha256sum | cut -d" " -f1); \
	  printf '{"type":"object","object":'"$$COINBASE_TX"'}\n'; \
	  sleep 0.5; \
	  printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":'"$$TIMESTAMP"',"miner":"grader","nonce":"0000000000000000000000000000000000000000000000000000000000000001","previd":"$(GENESIS_ID)","txids":["'"$$COINBASE_TXID"'"],"type":"block"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_pow_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_pow_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  cat $$OUTFILE; \
	  echo "✓ Block with invalid PoW rejected"; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Block with invalid PoW not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 6: Transaction spending non-existent UTXO
test_block_utxo_not_exists:
	@echo "== test_block_utxo_not_exists =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-utxo" | sha256sum | cut -c1-64); \
	  FAKE_TXID=$$(echo "$$TIMESTAMP-fake" | sha256sum | cut -d' ' -f1); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"inputs":[{"outpoint":{"index":0,"txid":"'"$$FAKE_TXID"'"},"sig":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":1000}],"type":"transaction"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_utxo_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_utxo_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  echo "✓ Transaction spending non-existent UTXO rejected"; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Transaction spending non-existent UTXO not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 7: Block with coinbase exceeding reward + fees (Debug, keine strenge Assertion)
test_block_excessive_coinbase:
	@echo "== test_block_excessive_coinbase (DEBUG) =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-excessive" | sha256sum | cut -c1-64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":60000000000000}],"type":"transaction"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_coinbase_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_coinbase_*.out | head -1); \
	echo "Note: Coinbase mit 60T (sollte im Block-Kontext zu Error führen)"; \
	cat $$OUTFILE; \
	rm -f $$OUTFILE

# Test 8: Block with unknown parent (UNKNOWN_OBJECT error)
test_block_missing_parent:
	@echo "== test_block_missing_parent =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-parent" | sha256sum | cut -c1-64); \
	  FAKE_PREVID=$$(echo "$$TIMESTAMP-previd" | sha256sum | cut -d' ' -f1); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  COINBASE_TX='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(echo "$$COINBASE_TX" | jq -Sc | sha256sum | cut -d' ' -f1); \
	  printf '{"type":"object","object":'"$$COINBASE_TX"'}\n'; \
	  sleep 0.5; \
	  printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":'"$$TIMESTAMP"',"miner":"grader","nonce":"000000000000000000000000000000000000000000000000000000000004e315","previd":"'"$$FAKE_PREVID"'","txids":["'"$$COINBASE_TXID"'"],"type":"block"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_parent_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_parent_*.out | head -1); \
	if grep -q '"name":"UNKNOWN_OBJECT"' $$OUTFILE; then \
	  echo "✓ Block with unknown parent rejected with UNKNOWN_OBJECT"; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Block with unknown parent not properly rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 9: Block should fetch unknown transactions
test_block_with_unknown_tx:
	@echo "== test_block_with_unknown_tx =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-fetch" | sha256sum | cut -c1-64); \
	  COINBASE_TX='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(echo "$$COINBASE_TX" | jq -Sc | sha256sum | cut -d' ' -f1); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":'"$$TIMESTAMP"',"miner":"grader","nonce":"000000000000000000000000000000000000000000000000000000000004e315","previd":"$(GENESIS_ID)","txids":["'"$$COINBASE_TXID"'"],"type":"block"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_unknown_tx_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_unknown_tx_*.out | head -1); \
	if grep -q '"type":"getobject"' $$OUTFILE; then \
	  echo "✓ Node requested unknown transaction"; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Node did not request unknown transaction"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 10: Coinbase must be at index 0 if present (Debug)
test_block_coinbase_position:
	@echo "== test_block_coinbase_position (DEBUG) =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY1=$$(echo "$$TIMESTAMP-pos1" | sha256sum | cut -c1-64); \
	  RAND_PUBKEY2=$$(echo "$$TIMESTAMP-pos2" | sha256sum | cut -c1-64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  TX1='{"height":0,"outputs":[{"pubkey":"'"$$RAND_PUBKEY1"'","value":10000000000000}],"type":"transaction"}'; \
	  TX1_TXID=$$(echo "$$TX1" | jq -Sc | sha256sum | cut -d' ' -f1); \
	  printf '{"type":"object","object":'"$$TX1"'}\n'; \
	  sleep 0.3; \
	  COINBASE_TX='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY2"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(echo "$$COINBASE_TX" | jq -Sc | sha256sum | cut -d' ' -f1); \
	  printf '{"type":"object","object":'"$$COINBASE_TX"'}\n'; \
	  sleep 1; \
	  echo "Note: Block mit coinbase nicht an Index 0 sollte invalid sein – Block muss separat gebaut werden."; \
	} | nc -v -v -w 5 localhost 18018 > /tmp/block_coinbase_pos_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_coinbase_pos_*.out | head -1); \
	cat $$OUTFILE; \
	rm -f $$OUTFILE

# Test 11: Block with multiple coinbase transactions (Debug)
test_block_multiple_coinbase:
	@echo "== test_block_multiple_coinbase (DEBUG) =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY1=$$(echo "$$TIMESTAMP-multi1" | sha256sum | cut -c1-64); \
	  RAND_PUBKEY2=$$(echo "$$TIMESTAMP-multi2" | sha256sum | cut -c1-64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  COINBASE1='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY1"'","value":25000000000000}],"type":"transaction"}'; \
	  printf '{"type":"object","object":'"$$COINBASE1"'}\n'; \
	  sleep 0.3; \
	  COINBASE2='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY2"'","value":25000000000000}],"type":"transaction"}'; \
	  printf '{"type":"object","object":'"$$COINBASE2"'}\n'; \
	  sleep 1; \
	  echo "Note: Zwei Coinbase-TXs im selben Block sollten invalid sein – Block muss separat gebaut werden."; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_multi_coinbase_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_multi_coinbase_*.out | head -1); \
	cat $$OUTFILE; \
	rm -f $$OUTFILE

# Test 12: Coinbase with inputs should be rejected
test_block_coinbase_with_inputs:
	@echo "== test_block_coinbase_with_inputs =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-cbinput" | sha256sum | cut -c1-64); \
	  FAKE_TXID=$$(echo "$$TIMESTAMP-cbfake" | sha256sum | cut -d' ' -f1); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"height":'"$$TIMESTAMP"',"inputs":[{"outpoint":{"index":0,"txid":"'"$$FAKE_TXID"'"},"sig":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":50000000000000}],"type":"transaction"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/coinbase_inputs_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/coinbase_inputs_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  echo "✓ Coinbase with inputs rejected"; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Coinbase with inputs not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 13: Valid transaction gossip to second peer (extra, tx-level)
test_block_gossip_valid:
	@echo "== test_block_gossip_valid (transaction gossip) =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-gossip" | sha256sum | cut -c1-64); \
	  mkfifo /tmp/grader2_gossip_$$TIMESTAMP 2>/dev/null || true; \
	  { \
	    printf '{"agent":"grader2","type":"hello","version":"0.10.0"}\n'; \
	    sleep 10; \
	  } | nc -v -w 15 localhost 18018 > /tmp/grader2_gossip_$$TIMESTAMP.out & \
	  GRADER2_PID=$$!; \
	  sleep 1; \
	  { \
	    printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	    sleep 0.2; \
	    printf '{"type":"object","object":{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":50000000000000}],"type":"transaction"}}\n'; \
	    sleep 2; \
	  } | nc -v -w 5 localhost 18018 >/dev/null; \
	  sleep 1; \
	  kill $$GRADER2_PID 2>/dev/null || true; \
	  if grep -q '"type":"ihaveobject"' /tmp/grader2_gossip_$$TIMESTAMP.out; then \
	    echo "✓ Valid transaction gossiped correctly"; \
	    rm -f /tmp/grader2_gossip_$$TIMESTAMP.out /tmp/grader2_gossip_$$TIMESTAMP; \
	    exit 0; \
	  else \
	    echo "✗ Valid transaction not gossiped"; \
	    cat /tmp/grader2_gossip_$$TIMESTAMP.out; \
	    rm -f /tmp/grader2_gossip_$$TIMESTAMP.out /tmp/grader2_gossip_$$TIMESTAMP; \
	    exit 1; \
	  fi; \
	}

# Test 14: UTXO state management - store and retrieve (eigentlich Objekt-Persistenz)
test_utxo_state_management:
	@echo "== test_utxo_state_management =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-utxomgmt" | sha256sum | cut -c1-64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  COINBASE_TX='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(echo "$$COINBASE_TX" | jq -Sc | sha256sum | cut -d' ' -f1); \
	  printf '{"type":"object","object":'"$$COINBASE_TX"'}\n'; \
	  sleep 1; \
	  printf '{"type":"getobject","objectid":"'"$$COINBASE_TXID"'"}\n'; \
	  sleep 1; \
	} | nc -v -w 10 localhost 18018 > /tmp/utxo_state_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/utxo_state_*.out | head -1); \
	if grep -q '"type":"object"' $$OUTFILE; then \
	  echo "✓ Transaction stored and retrievable"; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Transaction not properly stored"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test 15: Transaction spending from non-coinbase tx in same block (Note/TODO)
test_block_tx_spending_same_block:
	@echo "== test_block_tx_spending_same_block =="
	@echo "Note: Non-coinbase transactions CAN spend outputs created in same block (TODO: echter Block-Test mit gültiger Signatur)."

# Test 16: Coinbase cannot be spent in same block (Note/TODO)
test_coinbase_spent_same_block:
	@echo "== test_coinbase_spent_same_block =="
	@echo "Note: Coinbase transactions CANNOT be spent in the same block (TODO: echter Block-Test mit gültiger Signatur)."

# Test 17: Block with invalid format (missing required fields)
test_block_invalid_format:
	@echo "== test_block_invalid_format =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":'"$$TIMESTAMP"',"type":"block"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_format_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_format_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE && grep -q '"name":"INVALID_FORMAT"' $$OUTFILE; then \
	  echo "✓ Block with missing fields rejected"; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Block with missing fields not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi



# don't touch these targets 
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

submission:
	mkdir -p _submission
	tar --exclude='./.idea' --exclude='./_submission' --exclude='./_test' --exclude='./.git' -czf _submission/submission.tgz .
	@echo Finished creating submission archive _submission/submission.tgz
	@echo Run make check-submission now to check if our automated grader will be able to connect to it

check-submission:
	rm -rf _test
	mkdir -p _test
	tar -xf _submission/submission.tgz -C _test

	$(MAKE) -C _test docker-build
	$(MAKE) -C _test docker-up
	
	@echo "Waiting 5 seconds for node to finish startup"
	sleep 5

	$(MAKE) run-tests
	
	$(MAKE) -C _test docker-down
	$(MAKE) remove-test
	@echo Test completed

remove-test:
	rm -rf _test

remove-submission:
	rm -rf _submission
