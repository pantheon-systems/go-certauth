#!/bin/sh
set -e

# reset/cleanup
cleanup() {
	rm -f -- ./*.pem ./*.crt ./*.key ./*.p12
}

# list certs/keys in current dir
list() {
	ls -l ./*.pem ./*.crt ./*.key ./*.p12
}

# create CA
create_ca() {
	echo "==> Creating new CA: ca.key, ca.crt"

	openssl req -new -newkey rsa:2048 -days 4650 -nodes -sha256 -x509 \
		-subj '/CN=test-CA/O=testco/C=US' \
		-keyout ca.key \
		-out ca.crt

	cat ca.key \
			ca.crt >ca.pem
}

# create a client key/cert signed by the CA.
# The first argument to this function is used for both the filenames and CN,
# the second argument is used as the OU.
#
# Example:
#    key_and_cert endpoint foo
# Results in:
#    - foo.key, foo.crt, foo.pem, foo.p12
#    - Cert subject: /OU=endpoint/CN=foo/
#
key_and_cert() {
	subj=$1
  name=$2
	if [ -z "$subj" ] || [ -z "$name" ]; then
		echo "usage: key_and_cert subject filename"
		return 1
	fi

	echo "==> Creating key/cert for '$name': $name.key, $name.crt, $name.p12"

	openssl req -new -newkey rsa:2048 -subj "$subj" -nodes \
		-keyout "$name.key" \
		-out "$name.csr"

	openssl x509 -req -days 3650 -set_serial "$RANDOM" -sha256 \
		-CA ca.crt \
		-CAkey ca.key \
		-extfile openssl-test.cfg \
		-extensions v3_ca \
		-in "$name.csr" \
		-out "$name.crt"

	cat "$name.key" \
			"$name.crt" >"$name.pem"

	openssl pkcs12 -export \
		-password pass:password \
		-in "$name.crt" \
		-inkey "$name.pem" \
		-out "$name.p12"
}

main() {
	cleanup
	create_ca
	key_and_cert "/OU=endpoint/CN=server" "server"
	key_and_cert "/OU=endpoint/CN=client1" "client1"
	key_and_cert "/OU=site/CN=client2" "client2"

	# show the files that were just created
	list
}

main "$@"
