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
run-tests:
	# Perform a simple connection check   
	make smoke
	make hello_on_connect
	make handshake_then_getpeers
	make defragmentation
	make invalid_before_hello
	make invalid_garbage
	make invalid_hello_missing_version
	make invalid_hello_nonnumeric_version
	make invalid_hello_wrong_semver
	make double_hello
	make reconnect
	make concurrency
	make test_peer_validation
	make test_object_exchange
	make test_object_exchange2
	make test_transaction_invalid_syntax
	make test_valid_transactions
	make test_transaction_invalid_tx_outpoint
	make test_transaction_invalid_signature
	make test_transaction_double_spending
	make test_transaction_invalid_tx_conservation
	make test_transaction_validation
	make test_gossiping_ihaveobject
	make test_tx_error_specific
	make test_tx_valid_coinbase 
	make test_tx_missing_outputs
	make test_tx_unknown_input
	make test_tx_gossip_on_valid
	make test_tx_no_gossip_on_invalid
	make test_send_object_after_gossip_request


# 0) Smoke: connect, see a hello, then send our hello + getpeers and see peers
smoke:
	@echo "== Smoke =="
	@{ \
	  timeout 3s nc -v -w 5 localhost 18018 | while IFS= read -r line; do echo "← Received: $$line"; done & \
	  pid=$$!; \
	  sleep 1; \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n' | nc -w 5 localhost 18018 >/dev/null || true; \
	  printf '{"type":"getpeers"}\n' | nc -w 5 localhost 18018 >/dev/null || true; \
	  wait $$pid || true; \
	}

# 1) Verify we receive a hello first upon connect (no data sent yet)
hello_on_connect:
	@echo "== hello_on_connect =="
	@timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line; \
	  echo "← Line 1: $$line"; \
	  if echo "$$line" | jq -e '.type == "hello"' > /dev/null 2>&1; then \
	    echo "✓ Valid hello message"; \
	  else \
	    echo "✗ Invalid hello message"; \
	    exit 1; \
	  fi; \
	}

# 2) Proper handshake: we answer with hello and immediately send getpeers; expect peers
handshake_then_getpeers:
	@echo "== handshake_then_getpeers =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"getpeers"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line1; \
	  echo "← Line 1: $$line1"; \
	  if echo "$$line1" | jq -e '.type == "hello"' > /dev/null 2>&1; then \
	    echo "✓ Valid hello message"; \
	  else \
	    echo "✗ Invalid hello message"; \
	  fi; \
	  \
	  IFS= read -r line2; \
	  echo "← Line 2: $$line2"; \
	  if echo "$$line2" | jq -e '.type == "getpeers"' > /dev/null 2>&1; then \
	    echo "✓ Valid getpeers echo"; \
	  else \
	    echo "✗ Invalid getpeers echo"; \
	  fi; \
	  \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "peers"' > /dev/null 2>&1; then \
	    echo "✓ Valid peers message"; \
	  else \
	    echo "✗ Invalid peers message"; \
	    exit 1; \
	  fi; \
	}

# 3) Defragmentation (same pattern)
defragmentation:
	@echo "== defragmentation =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"getpe'; \
	  sleep 0.1; \
	  printf 'ers"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line1; \
	  echo "← Line 1: $$line1"; \
	  if echo "$$line1" | jq -e '.type == "hello"' > /dev/null 2>&1; then \
	    echo "✓ Valid hello message"; \
	  else \
	    echo "✗ Invalid hello message"; \
	  fi; \
	  \
	  IFS= read -r line2; \
	  echo "← Line 2: $$line2"; \
	  if echo "$$line2" | jq -e '.type == "getpeers"' > /dev/null 2>&1; then \
	    echo "✓ Valid getpeers echo"; \
	  else \
	    echo "✗ Invalid getpeers echo"; \
	  fi; \
	  \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "peers"' > /dev/null 2>&1; then \
	    echo "✓ Valid peers message"; \
	  else \
	    echo "✗ Invalid peers message"; \
	    exit 1; \
	  fi; \
	}

# 4) INVALID_HANDSHAKE
invalid_before_hello:
	@echo "== invalid_before_hello =="
	@{ \
	  printf '{"type":"getpeers"}\n'; \
	  sleep 1; \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 1; \
	} | timeout 5s nc -v -w 10 localhost 18018 | { \
	  IFS= read -r line1; \
	  echo "← Line 1: $$line1"; \
	  IFS= read -r line2; \
	  echo "← Line 2: $$line2"; \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "error" and .name == "INVALID_HANDSHAKE"' > /dev/null 2>&1; then \
	    echo "✓ Error is INVALID_HANDSHAKE"; \
	  else \
	    echo "✗ Error is not INVALID_HANDSHAKE"; \
	    exit 1; \
	  fi; \
	}

# 5) INVALID_FORMAT (garbage)
invalid_garbage:
	@echo "== invalid_garbage =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf 'Wbgygvf7rgtyv7tfbgy{{{\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line1; \
	  IFS= read -r line2; \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "error" and .name == "INVALID_FORMAT"' > /dev/null 2>&1; then \
	    echo "✓ Error is INVALID_FORMAT"; \
	  else \
	    echo "✗ Error is not INVALID_FORMAT"; \
	    exit 1; \
	  fi; \
	}

# 6) Invalid hello (missing version)
invalid_hello_missing_version:
	@echo "== invalid_hello_missing_version =="
	@{ \
	  printf '{"type":"hello"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line1; \
	  IFS= read -r line2; \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "error" and .name == "INVALID_FORMAT"' > /dev/null 2>&1; then \
	    echo "✓ Error type is INVALID_FORMAT"; \
	  else \
	    echo "✗ Wrong error type"; \
	    exit 1; \
	  fi; \
	}

# 7) Invalid hello (nonnumeric version)
invalid_hello_nonnumeric_version:
	@echo "== invalid_hello_nonnumeric_version =="
	@{ \
	  printf '{"type":"hello","version":"jd3.x"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line1; \
	  IFS= read -r line2; \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "error" and .name == "INVALID_FORMAT"' > /dev/null 2>&1; then \
	    echo "✓ Error type is INVALID_FORMAT"; \
	  else \
	    echo "✗ Wrong error type"; \
	    exit 1; \
	  fi; \
	}

# 8) Invalid hello (wrong semver)
invalid_hello_wrong_semver:
	@echo "== invalid_hello_wrong_semver =="
	@{ \
	  printf '{"type":"hello","version":"5.8.2"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line1; \
	  IFS= read -r line2; \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "error" and (.name == "INVALID_FORMAT" or .name == "INVALID_HANDSHAKE")' > /dev/null 2>&1; then \
	    echo "✓ Error type is valid"; \
	  else \
	    echo "✗ Wrong error type"; \
	    exit 1; \
	  fi; \
	}

# 9) Double hello → INVALID_HANDSHAKE
double_hello:
	@echo "== double_hello =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"hello","version":"0.10.0"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line1; \
	  IFS= read -r line2; \
	  IFS= read -r line3; \
	  echo "← Line 3: $$line3"; \
	  if echo "$$line3" | jq -e '.type == "error" and .name == "INVALID_HANDSHAKE"' > /dev/null 2>&1; then \
	    echo "✓ Error is INVALID_HANDSHAKE"; \
	  else \
	    echo "✗ Error is not INVALID_HANDSHAKE"; \
	    exit 1; \
	  fi; \
	}

# 10) Reconnect works cleanly
reconnect:
	@echo "== reconnect =="
	@timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line; \
	  echo "← Connection 1: $$line"; \
	  if echo "$$line" | jq -e '.type == "hello"' > /dev/null 2>&1; then \
	    echo "✓ First connection received hello"; \
	  else \
	    echo "✗ First connection failed"; \
	  fi; \
	} || true
	@sleep 0.5
	@timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line; \
	  echo "← Connection 2: $$line"; \
	  if echo "$$line" | jq -e '.type == "hello"' > /dev/null 2>&1; then \
	    echo "✓ Second connection received hello"; \
	  else \
	    echo "✗ Second connection failed"; \
	    exit 1; \
	  fi; \
	} || true

# 11) Two simultaneous connections are accepted
concurrency:
	@echo "== concurrency =="
	@(timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line; \
	  echo "← Connection A: $$line"; \
	  if echo "$$line" | jq -e '.type == "hello"' > /dev/null 2>&1; then \
	    echo "✓ Connection A received hello"; \
	  fi; \
	} &) ; \
	(timeout 3s nc -v -w 5 localhost 18018 | { \
	  IFS= read -r line; \
	  echo "← Connection B: $$line"; \
	  if echo "$$line" | jq -e '.type == "hello"' > /dev/null 2>&1; then \
	    echo "✓ Connection B received hello"; \
	  fi; \
	} &) ; \
	wait || true

# Peer validation tests
test_peer_validation:
	@echo "== test_peer_validation =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"peers","peers":["256.2.3.4:18018"]}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "error" and .name == "INVALID_FORMAT"' > /dev/null 2>&1; then \
	      echo "✓ Invalid IP rejected"; \
	      exit 0; \
	    fi; \
	  done; \
	  echo "✗ No error received for invalid peer"; \
	  exit 1; \
	}

# This is the first Sample Testcase from Task 2
# Grader 1 sends a new valid transaction object and then requests the same object, Grader 1 should receive the object.
# Object exchange tests
test_object_exchange:
	@echo "== test_object_exchange =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50}],"type":"transaction"}}\n'; \
	  sleep 0.5; \
	  printf '{"type":"getobject","objectid":"cc41ac3a9e77cfaaea136e5570c8bdc883d7b5c9c6a9d5ab96d320b443db4a72"}\n'; \
	} | timeout 5s nc -v -w 10 localhost 18018 | { \
	  ok_object=0; \
	  ok_ihave=0; \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "object"' > /dev/null 2>&1; then \
	      received_obj=$$(echo "$$line" | jq -c '.object'); \
	      expected_obj='{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50}],"type":"transaction"}'; \
	      expected_obj=$$(echo "$$expected_obj"); \
	      if [ "$$received_obj" = "$$expected_obj" ]; then \
	        echo "✓ Object matches exactly"; \
			ok_object=1; \
	      else \
	        echo "✗ Object doesn't match"; \
	        echo "Expected: $$expected_obj"; \
	        echo "Received: $$received_obj"; \
	        exit 1; \
	      fi; \
	    fi; \
		if echo "$$line" | jq -e '.type == "ihaveobject"' > /dev/null 2>&1; then \
	        echo "✓ After object message received, ihaveobject is sent."; \
			ok_ihave=1; \
	    fi; \
	  done; \
	  if [ $$ok_object -eq 1 ] && [ $$ok_ihave -eq 1 ]; then \
	  	echo "✓ Both object and ihaveobject received"; \
	    exit 0; \
	  elif [ $$ok_object -eq 1 ] && [ $$ok_ihave -eq 0 ]; then \
	    echo "✗ No ihaveobject received"; \
	    exit 1; \
	  elif [ $$ok_object -eq 0 ] && [ $$ok_ihave -eq 1 ]; then \
	    echo "✗ No object received"; \
	    exit 1; \
	  else \
	    echo "✗ Neither object nor ihaveobject received"; \
	    exit 1; \
	  fi; \
	}

# This is the 4. Sample Testcase from Task 2
# If Grader 1 sends an ihaveobject message with the id of a new object, Grader 1 must receive a getobject message with the same object id.
test_object_exchange2:
	@echo "== test_object_exchange2 =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"ihaveobject", "objectid":"cc41ac3a9e77cfaaea136e5570c8bdc883d7b5c9c6a9d5ab96d320b443db4a78" }\n'; \
	} | timeout 5s nc -v -w 10 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "getobject"' > /dev/null 2>&1; then \
	      if echo "$$line" | grep -q 'cc41ac3a9e77cfaaea136e5570c8bdc883d7b5c9c6a9d5ab96d320b443db4a78'; then \
	        echo "✓ Received getobject with correct objectid"; \
	        exit 0; \
	      fi; \
	    fi; \
	  done; \
	  echo "✗ No getobject received"; \
	  exit 1; \
	}

# Transaction validation tests
test_transaction_validation:
	@echo "== test_transaction_validation =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50000000000000}],"type":"transaction"}}\n'; \
	  sleep 0.5; \
	  printf '{"type":"object","object":{"inputs":[{"outpoint":{"index":0,"txid":"d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"},"sig":"6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"}],"outputs":[{"pubkey":"b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985","value":10},{"pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9","value":49999999999990}],"type":"transaction"}}\n'; \
	} | timeout 5s nc -v -w 10 localhost 18018 | { \
	  ihave_count=2; \
	  error_received=0; \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "ihaveobject"' > /dev/null 2>&1; then \
	      ihave_count=$$((ihave_count + 1)); \
	    fi; \
	    if echo "$$line" | jq -e '.type == "error"' > /dev/null 2>&1; then \
	      error_received=1; \
	    fi; \
	  done; \
	  if [ $$error_received -eq 2 ]; then \
	    echo "✗ Received error for valid transaction"; \
	    exit 1; \
	  elif [ $$ihave_count -ge 2 ]; then \
	    echo "✓ Valid transaction accepted and gossiped"; \
	    exit 0; \
	  else \
	    echo "✗ Expected 2 ihaveobject messages (one for each transaction), got $$ihave_count"; \
	    exit 1; \
	  fi; \
	}

test_transaction_invalid_syntax:
	@echo "== test_transaction_invalid_syntax =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"unknown_property":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50}],"type":"transaction"}}\n'; \
	} | timeout 5s nc -v -w 10 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "error" and .name == "INVALID_FORMAT"' > /dev/null 2>&1; then \
	      echo "✓ Received INVALID_FORMAT error"; \
	      exit 0; \
	    fi; \
	  done; \
	  echo "✗ No error received"; \
	  exit 1; \
	}

test_valid_transactions:
	@echo "== test_valid_transactions =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50000000000000}],"type":"transaction"},"type":"object"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"inputs":[{"outpoint":{"index":0,"txid":"d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"},"sig":"6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"}],"outputs":[{"pubkey":"b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985","value":10},{"pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9","value":49999999999990}],"type":"transaction"},"type":"object"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"getobject","objectid":"d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"getobject","objectid":"895ca2bea390b7508f780c7174900a631e73905dcdc6c07a6b61ede2ebd4033f"}\n'; \
	} | timeout 5s nc -v -w 10 localhost 18018 | { \
	  seen_first=0; \
	  seen_second=0; \
	  expected_first='{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50000000000000}],"type":"transaction"}'; \
	  expected_first=$$(echo "$$expected_first"); \
	  expected_second='{"inputs":[{"outpoint":{"index":0,"txid":"d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"},"sig":"6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"}],"outputs":[{"pubkey":"b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985","value":10},{"pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9","value":49999999999990}],"type":"transaction"}'; \
	  expected_second=$$(echo "$$expected_second"); \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "object"' > /dev/null 2>&1; then \
	      received_obj=$$(echo "$$line" | jq -c '.object'); \
	      if [ $$seen_first -eq 0 ]; then \
	        echo "→ Checking first object..."; \
	        if [ "$$received_obj" = "$$expected_first" ]; then \
	          echo "✓ First object matches expected"; \
	          seen_first=1; \
	          continue; \
	        else \
	          echo "✗ First object doesn't match"; \
	          echo "Expected: $$expected_first"; \
	          echo "Received: $$received_obj"; \
	          exit 1; \
	        fi; \
	      else \
	        echo "→ Checking second object..."; \
	        if [ "$$received_obj" = "$$expected_second" ]; then \
	          echo "✓ Second object matches expected"; \
	          seen_second=1; \
	          exit 0; \
	        else \
	          echo "✗ Second object doesn't match"; \
	          echo "Expected: $$expected_second"; \
	          echo "Received: $$received_obj"; \
	          exit 1; \
	        fi; \
	      fi; \
	    fi; \
	  done; \
	  if [ $$seen_first -eq 1 ] && [ $$seen_second -eq 1 ]; then \
	    exit 0; \
	  else \
	    echo "✗ Did not receive both expected objects"; \
	    exit 1; \
	  fi; \
	}

test_transaction_invalid_tx_outpoint:
	@echo "== test_transaction_invalid_tx_outpoint =="
	@{ \
      printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50000000000000}],"type":"transaction"},"type":"object"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"inputs":[{"outpoint":{"index":9999,"txid":"d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"},"sig":"6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"}],"outputs":[{"pubkey":"b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985","value":10},{"pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9","value":49999999999990}],"type":"transaction"},"type":"object"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "error" and .name == "INVALID_TX_OUTPOINT"' > /dev/null 2>&1; then \
	      echo "✓ Invalid transaction with bad outpoint rejected"; \
	      exit 0; \
	    fi; \
	  done; \
	  echo "✗ INVALID_TX_OUTPOINT error not received"; \
	  exit 1; \
	}

test_transaction_invalid_signature:
	@echo "== test_transaction_invalid_signature =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50000000000000}],"type":"transaction"},"type":"object"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"inputs":[{"outpoint":{"index":0,"txid":"d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"},"sig":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],"outputs":[{"pubkey":"b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985","value":10},{"pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9","value":49999999999990}],"type":"transaction"},"type":"object"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "error" and .name == "INVALID_TX_SIGNATURE"' > /dev/null 2>&1; then \
	      echo "✓ Invalid transaction with bad signature rejected"; \
	      exit 0; \
	    fi; \
	  done; \
	  echo "✗ INVALID_TX_SIGNATURE error not received"; \
	  exit 1; \
	}


test_transaction_double_spending:
	@echo "== test_transaction_double_spending =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"height":0,"outputs":[{"pubkey":"cd90f3df2116b26bca1f2bd30a75e23099d62ad917ae21cde0d0af99ae368e86","value":50000000000000}],"type":"transaction"},"type":"object"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"inputs":[{"outpoint":{"index":0,"txid":"e3e8ff71785e1bd9b2650acf48ed1a647b72d96862fd80c54fb912ce2d964963"},"sig":"bfe3bc1f04d83b1ee5e918a8913e6c176ebee651eca2d445159d04e4bd56d78fd3d6b8d999b567fb4bae638d3360568cbaab8ac4be6262140f78b7f1a0c71201"},{"outpoint":{"index":0,"txid":"e3e8ff71785e1bd9b2650acf48ed1a647b72d96862fd80c54fb912ce2d964963"},"sig":"bfe3bc1f04d83b1ee5e918a8913e6c176ebee651eca2d445159d04e4bd56d78fd3d6b8d999b567fb4bae638d3360568cbaab8ac4be6262140f78b7f1a0c71201"}],"outputs":[{"pubkey":"b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985","value":50000000000000},{"pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9","value":50000000000000}],"type":"transaction"},"type":"object"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "error" and .name == "INVALID_TX_CONSERVATION"' > /dev/null 2>&1; then \
	      echo "✓ Double spending transaction rejected"; \
	      exit 0; \
	    fi; \
	  done; \
	  echo "✗ Double spending rejection not received"; \
	  exit 1; \
	}

test_transaction_invalid_tx_conservation:
	@echo "== test_transaction_invalid_tx_conservation =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":50000000000000}],"type":"transaction"},"type":"object"}\n'; \
	  sleep 0.2; \
	  printf '{"object":{"inputs":[{"outpoint":{"index":0,"txid":"e3e8ff71785e1bd9b2650acf48ed1a647b72d96862fd80c54fb912ce2d964963"},"sig":"375d15b69bab5d884444c79a383c42ba9819e69dd0009084e13b2b8381a3d0c02e4a8bde3f4d5ebba6e90092331ad44358b54e92c099b1c5fd9b752266ae730f"}],"outputs":[{"pubkey":"b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985","value":50000000000001}],"type":"transaction"},"type":"object"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← $$line"; \
	    if echo "$$line" | jq -e '.type == "error" and .name == "INVALID_TX_CONSERVATION"' > /dev/null 2>&1; then \
	      echo "✓ Invalid transaction with bad conservation rejected"; \
	      exit 0; \
	    fi; \
	  done; \
	  echo "✗ INVALID_TX_CONSERVATION error not received"; \
	  exit 1; \
	}

# Gossiping test - requires two connections
# This is the third Sample Testcase from Task 2
# I Grader 1 sends a new valid transaction object, Grader 2 must receive an ihaveobject message with the object id.
test_gossiping_ihaveobject:
	@echo "== test_gossiping =="
	@{ \
	  mkfifo /tmp/grader2_pipe 2>/dev/null || true; \
	  { \
	    printf '{"agent":"grader2","type":"hello","version":"0.10.0"}\n'; \
	    sleep 10; \
	  } | nc -v -w 15 localhost 18018 > /tmp/grader2_output & \
	  GRADER2_PID=$$!; \
	  sleep 1; \
	  { \
	    printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	    sleep 0.2; \
	    printf '{"type":"object","object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":100000000000}],"type":"transaction"}}\n'; \
	    sleep 2; \
	  } | nc -v -w 5 localhost 18018 >/dev/null; \
	  sleep 1; \
	  kill $$GRADER2_PID 2>/dev/null || true; \
	  if grep -q '"type":"ihaveobject"' /tmp/grader2_output; then \
	    echo "✓ Transaction gossiped to Grader 2"; \
	    rm -f /tmp/grader2_output /tmp/grader2_pipe; \
	    exit 0; \
	  else \
	    echo "✗ Transaction not gossiped to Grader 2"; \
	    cat /tmp/grader2_output; \
	    rm -f /tmp/grader2_output /tmp/grader2_pipe; \
	    exit 1; \
	  fi; \
	}

##
# If Grader 1 sends a new valid transaction object and then Grader 2 requests the same object, Grader 2 should receive the object
# This is the second Sample Testcase from Task 2
test_send_object_after_gossip_request:
	@echo "== test_gossiping =="
	@{ \
	  mkfifo /tmp/grader2_pipe 2>/dev/null || true; \
	  { \
	    printf '{"agent":"grader2","type":"hello","version":"0.10.0"}\n'; \
	    sleep 2; \
		printf '{"type":"getobject","objectid":"e94969421da0fa3bf603aa10b81bfc23cc7c75ecba8385ed3bb785e8d0bcb4e5"}\n'; \
		sleep 2; \
	  } | nc -v -w 15 localhost 18018 > /tmp/grader2_output & \
	  GRADER2_PID=$$!; \
	  sleep 1; \
	  { \
	    printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	    sleep 0.2; \
	    printf '{"type":"object","object":{"height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":800000000}],"type":"transaction"}}\n'; \
	    sleep 2; \
	  } | nc -v -w 5 localhost 18018 >/dev/null; \
	  sleep 3; \
	  kill $$GRADER2_PID 2>/dev/null || true; \
	  if grep -q '"type":"ihaveobject"' /tmp/grader2_output; then \
	    echo "✓ Transaction gossiped to Grader 2"; \
	  else \
	    echo "✗ Transaction not gossiped to Grader 2"; \
	    cat /tmp/grader2_output; \
	    rm -f /tmp/grader2_output /tmp/grader2_pipe; \
	    exit 1; \
	  fi; \
	  if grep -q '"type":"object"' /tmp/grader2_output; then \
	    echo "✓ Grader 2 received the object upon request"; \
	    rm -f /tmp/grader2_output /tmp/grader2_pipe; \
	    exit 0; \
	  else \
	    echo "✗ Grader 2 did not receive the object upon request"; \
	    cat /tmp/grader2_output; \
	    rm -f /tmp/grader2_output /tmp/grader2_pipe; \
	    exit 1; \
	  fi; \
	}

#
# ==================================================
#     Here start the transaction validation tests:
# ==================================================
#


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


test_tx_valid_coinbase:
	@echo "== test_tx_valid_coinbase =="
	@{ \
	  printf '{"agent":"tx-tester","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"type":"transaction","height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":5000000}]}}\n'; \
	  sleep 0.5; \
	} | nc -v -w 5 localhost 18018 > /tmp/tx_valid_coinbase.out
	@grep -v "JSON parse error" /tmp/tx_valid_coinbase.out > /tmp/tx_valid_coinbase.filtered || true
	@if grep -q '"type":"error"' /tmp/tx_valid_coinbase.filtered; then \
		echo "✗ Node rejected valid coinbase tx"; \
		cat /tmp/tx_valid_coinbase.filtered; \
		rm -f /tmp/tx_valid_coinbase.out /tmp/tx_valid_coinbase.filtered; \
		exit 1; \
	else \
	  echo "✓ Node accepted valid coinbase tx"; \
	  rm -f /tmp/tx_valid_coinbase.out /tmp/tx_valid_coinbase.filtered; \
	fi


test_tx_missing_outputs:
	@echo "== test_tx_missing_outputs =="
	@{ \
	  printf '{"agent":"tx-tester","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"type":"transaction","height":0}}\n'; \
	  sleep 0.5; \
	} | nc -v -w 5 localhost 18018 > /tmp/tx_missing_outputs.out 2>&1
	@grep -v "JSON parse error" /tmp/tx_missing_outputs.out > /tmp/tx_missing_outputs.filtered || true 
	@if grep -q '"type":"error"' /tmp/tx_missing_outputs.filtered; then \
	  echo "✓ Node rejected tx without outputs (expected)"; \
	  cat /tmp/tx_missing_outputs.filtered; \
	  rm -f /tmp/tx_missing_outputs.out /tmp/tx_missing_outputs.filtered; \
	else \
	  echo "✗ Node did NOT reject tx without outputs"; \
	  cat /tmp/tx_missing_outputs.filtered; \
	  rm -f /tmp/tx_missing_outputs.out /tmp/tx_missing_outputs.filtered; \
	  exit 1; \
	fi


test_tx_unknown_input:
	@echo "== test_tx_unknown_input =="
	@{ \
	  printf '{"agent":"tx-tester","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"type":"transaction","inputs":[{"outpoint":{"txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","index":0},"sig":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":1000}]}}\n'; \
	  sleep 0.5; \
	} | nc -v -w 5 localhost 18018 > /tmp/tx_unknown_input.out
	@if grep -q '"type":"error"' /tmp/tx_unknown_input.out; then \
	  echo "✓ Node rejected tx with unknown input (expected)"; \
	  cat /tmp/tx_unknown_input.out; \
	  rm -f /tmp/tx_unknown_input.out; \
	else \
	  echo "✗ Node did NOT reject tx with unknown input"; \
	  cat /tmp/tx_unknown_input.out; \
	  rm -f /tmp/tx_unknown_input.out; \
	  exit 1; \
	fi


test_tx_no_gossip_on_invalid:
	@echo "== test_tx_no_gossip_on_invalid =="
	@{ \
	  # Grader 2: just connect and wait to see if we get a gossip msg \
	  printf '{"agent":"grader2","type":"hello","version":"0.10.0"}\n'; \
	  sleep 4; \
	} | nc -v -w 10 localhost 18018 > /tmp/invalid_grader2.out 2>&1 & \
	GRADER2_PID=$$!; \
	sleep 1; \
	{ \
	  # Grader 1: send hello + INVALID transaction (missing outputs) \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"type":"transaction","height":0}}\n'; \
	  sleep 0.5; \
	} | nc -v -w 5 localhost 18018 > /tmp/invalid_grader1.out 2>&1; \
	# give the node a moment to possibly (wrongly) gossip \
	sleep 1; \
	kill $$GRADER2_PID 2>/dev/null || true; \
	# filter out the JSON parse noise \
	grep -v "JSON parse error" /tmp/invalid_grader1.out > /tmp/invalid_grader1.filtered || true; \
	grep -v "JSON parse error" /tmp/invalid_grader2.out > /tmp/invalid_grader2.filtered || true; \
	# 1) Grader 1 MUST get an error \
	if grep -q '"type":"error"' /tmp/invalid_grader1.filtered; then \
	  echo "✓ Sender (Grader 1) received error for invalid tx"; \
	else \
	  echo "✗ Sender (Grader 1) did NOT receive error for invalid tx"; \
	  cat /tmp/invalid_grader1.filtered; \
	  rm -f /tmp/invalid_grader*.out /tmp/invalid_grader*.filtered; \
	  exit 1; \
	fi; \
	# 2) Grader 2 MUST NOT see ihaveobject \
	if grep -q '"type":"ihaveobject"' /tmp/invalid_grader2.filtered; then \
	  echo "✗ Invalid tx was gossiped to Grader 2 (must NOT happen)"; \
	  cat /tmp/invalid_grader2.filtered; \
	  rm -f /tmp/invalid_grader*.out /tmp/invalid_grader*.filtered; \
	  exit 1; \
	else \
	  echo "✓ Invalid tx was NOT gossiped to Grader 2"; \
	fi; \
	rm -f /tmp/invalid_grader*.out /tmp/invalid_grader*.filtered; \
	exit 0


test_tx_gossip_on_valid:
	@echo "== test_tx_gossip_on_valid =="
	@{ \
	  # Grader 2: wait to receive gossip \
	  printf '{"agent":"grader2","type":"hello","version":"0.10.0"}\n'; \
	  sleep 4; \
	} | nc -v -w 10 localhost 18018 > /tmp/valid_grader2.out 2>&1 & \
	GRADER2_PID=$$!; \
	sleep 1; \
	{ \
	  # Grader 1: send hello + VALID transaction \
	  printf '{"agent":"grader1","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"object","object":{"type":"transaction","height":0,"outputs":[{"pubkey":"85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b","value":500000000}]}}\n'; \
	  sleep 0.5; \
	} | nc -v -w 5 localhost 18018 > /tmp/valid_grader1.out 2>&1; \
	sleep 1; \
	kill $$GRADER2_PID 2>/dev/null || true; \
	grep -v "JSON parse error" /tmp/valid_grader1.out > /tmp/valid_grader1.filtered || true; \
	grep -v "JSON parse error" /tmp/valid_grader2.out > /tmp/valid_grader2.filtered || true; \
	# 1) Grader 1 MUST NOT get an error \
	if grep -q '"type":"error"' /tmp/valid_grader1.filtered; then \
	  echo "✗ Sender (Grader 1) got an error for a valid tx"; \
	  cat /tmp/valid_grader1.filtered; \
	  rm -f /tmp/valid_grader*.out /tmp/valid_grader*.filtered; \
	  exit 1; \
	else \
	  echo "✓ Sender (Grader 1) did NOT get an error (good)"; \
	fi; \
	# 2) Grader 2 MUST get ihaveobject \
	if grep -q '"type":"ihaveobject"' /tmp/valid_grader2.filtered; then \
	  echo "✓ Valid tx was gossiped to Grader 2"; \
	  cat /tmp/valid_grader2.filtered; \
	  rm -f /tmp/valid_grader*.out /tmp/valid_grader*.filtered; \
	  exit 0; \
	else \
	  echo "✗ Valid tx was NOT gossiped to Grader 2"; \
	  cat /tmp/valid_grader2.filtered; \
	  rm -f /tmp/valid_grader*.out /tmp/valid_grader*.filtered; \
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
