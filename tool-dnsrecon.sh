for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && dnsrecon -d $target -c OUT-WEB-BIRD/$target/$target-dnsrecon ;done
