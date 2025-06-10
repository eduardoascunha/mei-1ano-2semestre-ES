#!/bin/bash

openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem -subj "/C=BR/ST=Rio de Janeiro/L=Niteroi/O=UFF/OU=Midiacom/CN=uminho.org/emailAddress=arthurazs@midiacom.uff.br"