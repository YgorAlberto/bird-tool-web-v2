for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && sublist3r -n -d $target | grep "$target" | grep -v "Enumerating" >> OUT-WEB-BIRD/$target/$target-sublist3r;done
