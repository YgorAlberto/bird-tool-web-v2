for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && fierce --domain $target >> OUT-WEB-BIRD/$target/$target-fierce;done
