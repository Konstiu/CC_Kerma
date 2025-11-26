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

GENESIS_ID := 00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee

run-tests:
	make test_valid_block_from_spec
	make test_tx_error_specific
	make test_invalid_transaction_alone
	make test_block_incorrect_target
	make test_block_invalid_pow
	make test_block_invalid_transaction_in_block
	make test_block_utxo_not_exists
	make test_block_missing_parent
	make test_block_with_unknown_tx
	make test_block_coinbase_position
	make test_block_excessive_coinbase

# Test: Example valid block from spec must be accepted and gossiped
test_valid_block_from_spec:
	@echo "== test_valid_block_from_spec =="
	@{ \
	  { \
	    printf '{"agent":"grader2","type":"hello","version":"0.10.0"}\n'; \
	    sleep 3; \
	  } | nc -v -w 15 localhost 18018 > /tmp/grader2_spec_block.out & \
	  GRADER2_PID=$$!; \
	  sleep 1; \
	  { \
	    printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	    sleep 0.2; \
	    printf '{"type":"object","object":{"height":1,"outputs":[{"pubkey":"3f0bc71a375b574e4bda3ddf502fe1afd99aa020bf6049adfe525d9ad18ff33f","value":50000000000000}],"type":"transaction"}}\n'; \
	    sleep 0.3; \
	    printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":1671148800,"miner":"grader","nonce":"00000000000000000000000000000000000000000000000000000000000463cf","note":"This block has a coinbase transaction","previd":"$(GENESIS_ID)","txids":["6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"],"type":"block"}}\n'; \
	    sleep 1; \
	  } | nc -v -w 10 localhost 18018 > /tmp/grader1_spec_block.out; \
	  sleep 1; \
	  wait $$GRADER2_PID 2>/dev/null || true; \
	  if grep -q '"type":"error"' /tmp/grader1_spec_block.out; then \
	    echo "✗ Example valid block rejected"; \
	    cat /tmp/grader1_spec_block.out; \
	    rm -f /tmp/grader1_spec_block.out /tmp/grader2_spec_block.out /tmp/grader2_spec_block; \
	    exit 1; \
	  fi; \
	  if grep -q '"type":"ihaveobject"' /tmp/grader2_spec_block.out && grep -q '000020cb0002575a71955763adf365c78182f0bb5bee767794ebc7346e0a2194' /tmp/grader2_spec_block.out; then \
	    echo "✓ Example valid block accepted and gossiped"; \
	    cat /tmp/grader2_spec_block.out; \
		cat /tmp/grader1_spec_block.out; \
	    rm -f /tmp/grader1_spec_block.out /tmp/grader2_spec_block.out /tmp/grader2_spec_block; \
	    exit 0; \
	  else \
	    echo "✗ Example valid block not gossiped"; \
	    cat /tmp/grader2_spec_block.out; \
		cat /tmp/grader1_spec_block.out; \
	    rm -f /tmp/grader1_spec_block.out /tmp/grader2_spec_block.out /tmp/grader2_spec_block; \
	    exit 1; \
	  fi; \
	}

## Test specific error for transaction with missing fields
test_tx_error_specific:
	@echo "== test_tx_error_specific =="
	@{ \
	  printf '{"agent":"tx-tester","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"type":"transaction","height":0}}\n'; \
	  sleep 0.5; \
	} | nc -v -w 5 localhost 18018 > /tmp/tx_error_specific.out
	@if grep -q '"type":"error"' /tmp/tx_error_specific.out; then \
	  if grep -q '"name":"INVALID_FORMAT"' /tmp/tx_error_specific.out; then \
	    echo "✓ Got correct INVALID_FORMAT error"; \
	    cat /tmp/tx_error_specific.out; \
	    rm -f /tmp/tx_error_specific.out; \
	  else \
	    echo "✗ Got error but not INVALID_FORMAT"; \
	    cat /tmp/tx_error_specific.out; \
	    rm -f /tmp/tx_error_specific.out; \
	    exit 1; \
	  fi; \
	else \
	  echo "✗ Did not get any error back"; \
	  cat /tmp/tx_error_specific.out; \
	  rm -f /tmp/tx_error_specific.out; \
	  exit 1; \
	fi

# Test: Invalid transaction (no outputs) must be rejected on its own
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
	  if grep -q '"name":"INVALID_FORMAT"' $$OUTFILE; then \
	    echo "✓ Invalid transaction rejected with INVALID_FORMAT"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	  else \
	    echo "⚠ Invalid transaction rejected but with wrong error name"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	    exit 1; \
	  fi; \
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
	  if grep -q '"name":"INVALID_ANCESTRY"' $$OUTFILE || grep -q '"name":"INVALID_FORMAT"' $$OUTFILE; then \
	    echo "✓ Block with invalid transaction rejected with correct error"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	  else \
	    echo "⚠ Block rejected but with unexpected error name"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	    exit 1; \
	  fi; \
	else \
	  echo "✗ Block with invalid transaction not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test: Block with incorrect target should be rejected
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
	  if grep -q '"name":"INVALID_FORMAT"' $$OUTFILE; then \
	    echo "✓ Block with incorrect target rejected with INVALID_FORMAT"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	  else \
	    echo "⚠ Block rejected but with wrong error name (expected INVALID_FORMAT)"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	    exit 1; \
	  fi; \
	else \
	  echo "✗ Block with incorrect target not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test: Block with invalid proof-of-work should be rejected
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
	    printf '{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":1671148800,"miner":"grader","nonce":"000000000000000000000000000000000000000000000000000000000004e315","note":"This block has a coinbase transaction","previd":"$(GENESIS_ID)","txids":["6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"],"type":"block"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_pow_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_pow_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  if grep -q '"name":"INVALID_BLOCK_POW"' $$OUTFILE; then \
	    echo "✓ Block with invalid PoW rejected with INVALID_BLOCK_POW"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	  else \
	    echo "⚠ Block rejected but with wrong error name (expected INVALID_BLOCK_POW)"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	    exit 1; \
	  fi; \
	else \
	  echo "✗ Block with invalid PoW not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test: Transaction spending non-existent UTXO
test_block_utxo_not_exists:
	@echo "== test_block_utxo_not_exists =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-utxo" | sha256sum | cut -c1-64); \
	  FAKE_TXID=$$(echo "$$TIMESTAMP-fake" | sha256sum | cut -d' ' -f1); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"inputs":[{"outpoint":{"index":0,"txid":"'"$$FAKE_TXID"'"},"sig":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":1000}],"type":"transaction"}}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_utxo_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_utxo_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  if grep -q '"name":"UNKNOWN_OBJECT"' $$OUTFILE || grep -q '"name":"UNFINDABLE_OBJECT"' $$OUTFILE; then \
	    echo "✓ Transaction spending non-existent UTXO rejected with correct error"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	  else \
	    echo "⚠ Transaction rejected but with unexpected error name"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	    exit 1; \
	  fi; \
	else \
	  echo "✗ Transaction spending non-existent UTXO not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test: Block with coinbase exceeding reward + fees
test_block_excessive_coinbase:
	@echo "== test_block_excessive_coinbase =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY=$$(echo "$$TIMESTAMP-excessive" | openssl dgst -blake2s256 | cut -d' ' -f2 | head -c 64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  COINBASE_TX='{"height":'"$$TIMESTAMP"',"outputs":[{"pubkey":"'"$$RAND_PUBKEY"'","value":60000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(python3 -c "import sys; sys.path.insert(0, '.'); from jcs import canonicalize; import hashlib; import json; tx = json.loads('$$COINBASE_TX'); print(hashlib.blake2s(canonicalize(tx)).hexdigest())"); \
	  printf '{"type":"object","object":'"$$COINBASE_TX"'}\n'; \
	  sleep 0.5; \
	  BLOCK=$$(python3 mine_block.py "$(GENESIS_ID)" "$$COINBASE_TXID" $$TIMESTAMP "0000abc000000000000000000000000000000000000000000000000000000000" 2>/dev/null); \
	  printf '{"type":"object","object":'"$$BLOCK"'}\n'; \
	  sleep 1; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_coinbase_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_coinbase_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  if grep -q '"name":"INVALID_BLOCK_COINBASE"' $$OUTFILE; then \
	    echo "✓ Block with excessive coinbase rejected with INVALID_BLOCK_COINBASE"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	  else \
	    echo "⚠ Block rejected but with wrong error name (expected INVALID_BLOCK_COINBASE)"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	    exit 1; \
	  fi; \
	else \
	  echo "✗ Block with excessive coinbase not rejected"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi



# Test: Block with unknown parent (UNKNOWN_OBJECT error)
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
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Block with unknown parent not properly rejected (expected UNKNOWN_OBJECT)"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test: Block should fetch unknown transactions
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
	  sleep 2; \
	} | nc -v -w 5 localhost 18018 > /tmp/block_unknown_tx_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/block_unknown_tx_*.out | head -1); \
	if grep -q '"type":"getobject"' $$OUTFILE; then \
	  echo "✓ Node requested unknown transaction"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	else \
	  echo "✗ Node did not request unknown transaction"; \
	  cat $$OUTFILE; \
	  rm -f $$OUTFILE; \
	  exit 1; \
	fi

# Test: Coinbase must be at index 0 if present
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



# Test: Double spend - same UTXO spent in two different transactions
test_double_spend:
	@echo "== test_double_spend =="
	@{ \
	  TIMESTAMP=$$(date +%s); \
	  RAND_PUBKEY1=$$(echo "$$TIMESTAMP-double1" | openssl dgst -blake2s256 | cut -d' ' -f2 | head -c 64); \
	  RAND_PUBKEY2=$$(echo "$$TIMESTAMP-double2" | openssl dgst -blake2s256 | cut -d' ' -f2 | head -c 64); \
	  RAND_PUBKEY3=$$(echo "$$TIMESTAMP-double3" | openssl dgst -blake2s256 | cut -d' ' -f2 | head -c 64); \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  COINBASE_TX='{"height":1,"outputs":[{"pubkey":"'"$$RAND_PUBKEY1"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID=$$(python3 -c "import sys; sys.path.insert(0, '.'); from jcs import canonicalize; import hashlib; import json; tx = json.loads('$$COINBASE_TX'); print(hashlib.blake2s(canonicalize(tx)).hexdigest())"); \
	  printf '{"type":"object","object":'"$$COINBASE_TX"'}\n'; \
	  sleep 0.3; \
	  BLOCK1=$$(python3 mine_block.py "$(GENESIS_ID)" "$$COINBASE_TXID" $$TIMESTAMP "0000abc000000000000000000000000000000000000000000000000000000000" 2>/dev/null); \
	  printf '{"type":"object","object":'"$$BLOCK1"'}\n'; \
	  sleep 0.5; \
	  BLOCK1_ID=$$(python3 -c "import sys; sys.path.insert(0, '.'); from jcs import canonicalize; import hashlib; import json; block = json.loads('$$BLOCK1'); print(hashlib.blake2s(canonicalize(block)).hexdigest())"); \
	  TX1='{"inputs":[{"outpoint":{"index":0,"txid":"'"$$COINBASE_TXID"'"},"sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}],"outputs":[{"pubkey":"'"$$RAND_PUBKEY2"'","value":25000000000000}],"type":"transaction"}'; \
	  TX1_TXID=$$(python3 -c "import sys; sys.path.insert(0, '.'); from jcs import canonicalize; import hashlib; import json; tx = json.loads('$$TX1'); print(hashlib.blake2s(canonicalize(tx)).hexdigest())"); \
	  printf '{"type":"object","object":'"$$TX1"'}\n'; \
	  sleep 0.3; \
	  COINBASE_TX2='{"height":2,"outputs":[{"pubkey":"'"$$RAND_PUBKEY1"'","value":50000000000000}],"type":"transaction"}'; \
	  COINBASE_TXID2=$$(python3 -c "import sys; sys.path.insert(0, '.'); from jcs import canonicalize; import hashlib; import json; tx = json.loads('$$COINBASE_TX2'); print(hashlib.blake2s(canonicalize(tx)).hexdigest())"); \
	  printf '{"type":"object","object":'"$$COINBASE_TX2"'}\n'; \
	  sleep 0.3; \
	  BLOCK2=$$(python3 mine_block.py "$$BLOCK1_ID" "$$COINBASE_TXID2,$$TX1_TXID" $$(($$TIMESTAMP + 1)) "0000abc000000000000000000000000000000000000000000000000000000000" 2>/dev/null); \
	  printf '{"type":"object","object":'"$$BLOCK2"'}\n'; \
	  sleep 0.5; \
	  TX2='{"inputs":[{"outpoint":{"index":0,"txid":"'"$$COINBASE_TXID"'"},"sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}],"outputs":[{"pubkey":"'"$$RAND_PUBKEY3"'","value":25000000000000}],"type":"transaction"}'; \
	  printf '{"type":"object","object":'"$$TX2"'}\n'; \
	  sleep 1; \
	} | nc -v -w 10 localhost 18018 > /tmp/double_spend_$$(date +%s).out
	@OUTFILE=$$(ls -t /tmp/double_spend_*.out | head -1); \
	if grep -q '"type":"error"' $$OUTFILE; then \
	  if grep -q '"name":"INVALID_TX_OUTPOINT"' $$OUTFILE; then \
	    echo "✓ Double spend rejected with INVALID_TX_OUTPOINT"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	  else \
	    echo "⚠ Double spend rejected but with different error"; \
	    cat $$OUTFILE; \
	    rm -f $$OUTFILE; \
	    exit 1; \
	  fi; \
	else \
	  echo "✗ Double spend not rejected"; \
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
