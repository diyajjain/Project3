#!/bin/bash

if [ "$#" -ne 2 ] || [ "$1" != "--origin-domain" ]; then
    echo "Usage: $0 --origin-domain domain"
    exit 1
fi

DOMAIN=$2

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout certs/cdn_key.pem \
    -out certs/cdn_cert.pem \
    -subj "/C=US/ST=NC/L=Durham/O=Duke University/OU=CS Department/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN"

echo "Certificate generated for $DOMAIN and stored in certs/"