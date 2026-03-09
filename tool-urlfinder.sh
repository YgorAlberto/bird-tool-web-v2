for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && echo $target | urlfinder | sort -u  > OUT-WEB-BIRD/$target/$target-URL-urlfinder ;done
