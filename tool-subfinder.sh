for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && subfinder --all -d $target >> OUT-WEB-BIRD/$target/$target-subfinder;done
