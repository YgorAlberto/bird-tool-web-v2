#for domain in $(cat subdomains-full.txt); do 
#    echo -n "$domain " 
#    curl -s -o /dev/null -w "%{http_code}\n" --connect-timeout 10 $domain
#done | grep -v "000" | cut -d " " -f 1 >> subdomains.txt


for domain in $(cat target-full.txt);do host $domain | grep -v NXDOMAIN | head -n 1 | cut -d " " -f 1 ; done >> target-tmp.txt | mv target-tmp.txt target.txt
