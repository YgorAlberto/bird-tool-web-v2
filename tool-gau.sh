for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && gau --subs $target >> OUT-WEB-BIRD/$target/$target-URL-gau;done
