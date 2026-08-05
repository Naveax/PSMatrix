.PHONY: test doctor example capability archive

test:
	python3 scripts/run_tests.py

doctor:
	./psmatrix doctor

example:
	./psmatrix test examples/hello.ps1 --runtime stable --install-missing

capability:
	./psmatrix test examples/core-capabilities.ps1 --runtime stable --install-missing

archive:
	tar --exclude='.psmatrix' --exclude='__pycache__' -czf ../psmatrix.tar.gz .
