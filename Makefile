.PHONY: docker-build docker-up run build clean make-submission check-submission remove-submission remove-test
.PHONY: run-tests smoke hello_on_connect handshake_then_getpeers defragmentation invalid_before_hello invalid_garbage invalid_hello_missing_version invalid_hello_nonnumeric_version invalid_hello_wrong_semver double_hello reconnect concurrency peers_persistence

run:
	cd src && python3 main.py

clean: remove-submission remove-test
	# add further actions if needed

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
	make peers_persistence

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
	  if echo "$$line3" | jq -e '.type == "error"' > /dev/null 2>&1; then \
	    echo "✓ Received error"; \
	    if echo "$$line3" | grep -q 'INVALID_HANDSHAKE'; then \
	      echo "✓ Error is INVALID_HANDSHAKE"; \
	    else \
	      echo "✗ Error is not INVALID_HANDSHAKE"; \
	      exit 1; \
	    fi; \
	  else \
	    echo "✗ No error received"; \
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
	  if echo "$$line3" | jq -e '.type == "error"' > /dev/null 2>&1; then \
	    echo "✓ Received error"; \
	    if echo "$$line3" | grep -q 'INVALID_FORMAT'; then \
	      echo "✓ Error is INVALID_FORMAT"; \
	    else \
	      echo "✗ Error is not INVALID_FORMAT"; \
	      exit 1; \
	    fi; \
	  else \
	    echo "✗ No error received"; \
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
	  if echo "$$line3" | jq -e '.type == "error"' > /dev/null 2>&1; then \
	    echo "✓ Received error"; \
		if echo "$$line3" | grep -E -q 'INVALID_FORMAT'; then \
	      echo "✓ Error type is valid"; \
	    else \
	      echo "✗ Wrong error type"; \
	      exit 1; \
	    fi; \
	  else \
	    echo "✗ No error received"; \
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
	  if echo "$$line3" | jq -e '.type == "error"' > /dev/null 2>&1; then \
	    echo "✓ Received error"; \
	    if echo "$$line3" | grep -E -q 'INVALID_FORMAT'; then \
	      echo "✓ Error type is valid"; \
	    else \
	      echo "✗ Wrong error type"; \
	      exit 1; \
	    fi; \
	  else \
	    echo "✗ No error received"; \
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
	  if echo "$$line3" | jq -e '.type == "error"' > /dev/null 2>&1; then \
	    echo "✓ Received error"; \
	    if echo "$$line3" | egrep -q 'INVALID_(FORMAT|HANDSHAKE)'; then \
	      echo "✓ Error type is valid"; \
	    else \
	      echo "✗ Wrong error type"; \
	      exit 1; \
	    fi; \
	  else \
	    echo "✗ No error received"; \
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
	  if echo "$$line3" | jq -e '.type == "error"' > /dev/null 2>&1; then \
	    echo "✓ Received error"; \
	    if echo "$$line3" | grep -q 'INVALID_HANDSHAKE'; then \
	      echo "✓ Error is INVALID_HANDSHAKE"; \
	    else \
	      echo "✗ Error is not INVALID_HANDSHAKE"; \
	      exit 1; \
	    fi; \
	  else \
	    echo "✗ No error received"; \
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

# 12) (Optional) Persistence sanity: send peers, reconnect, expect your node to remember them
peers_persistence:
	@echo "== peers_persistence =="
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"peers","peers":["pink.fluffy.unicorn:4242","128.130.122.74:18018"]}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  while IFS= read -r line; do \
	    echo "← Received: $$line"; \
	  done; \
	} >/dev/null || true
	@sleep 0.5
	@{ \
	  printf '{"agent":"gangang","type":"hello","version":"0.10.0"}\n'; \
	  sleep 0.2; \
	  printf '{"type":"getpeers"}\n'; \
	} | timeout 3s nc -v -w 5 localhost 18018 | { \
	  found=0; \
	  while IFS= read -r line; do \
	    echo "← Received: $$line"; \
	    if echo "$$line" | grep -E '"pink\.fluffy\.unicorn:4242"|"128\.130\.122\.74:18018"' > /dev/null; then \
	      found=1; \
	    fi; \
	  done; \
	  if [ $$found -eq 1 ]; then \
	    echo "✓ Peers persisted"; \
	  else \
	    echo "✗ Peers not found"; \
	    exit 1; \
	  fi; \
	}

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
