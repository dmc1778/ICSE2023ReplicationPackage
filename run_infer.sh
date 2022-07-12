#!/bin/bash

cd $1

infer capture --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc $2
infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc $2

rm -rf infer-out
