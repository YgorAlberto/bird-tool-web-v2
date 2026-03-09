
for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && assetfinder -subs-only $target >> OUT-WEB-BIRD/$target/$target-assetfinder ;done
