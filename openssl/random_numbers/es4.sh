#!/bin/bash

rand_h1=0x$(openssl rand -hex 32)

rand_h2=0x$(openssl rand -hex 32)

rand_res=$(( rand_h1 + rand_h2 ))

rand_res_mod=$(( rand_res % (2^256) ))

echo "The two random numbers are $rand_h1 and $rand_h1. The integer modular sum is $rand_res_mod"