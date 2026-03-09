#!/bin/bash
cd OUT-WEB-BIRD/
target=$(cat ../target.txt)
grep -riah ".$target" | grep -v "grep" | grep -v "Trying" | grep -v "Scraping" | grep -v "\-\-\-" |grep -v "IN" | cut -d " " -f 1 | grep -via "\.arpa" | grep ".$target" | grep -via http | sort -u > ../target-full.txt

