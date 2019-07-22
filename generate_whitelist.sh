#/bin/sh

# Ensure some files have been passed.
if [ "x$*" == "x" ]; then
    echo "Usage: $0 [whitelist_files+]" >&2
    exit -1
fi

cat << EOF
#include <ipmiwhitelist.hpp>

const std::vector<netfncmd_tuple> whitelist = {

EOF

# Output each row of whitelist vector.
# Concatenate all the passed files.
# Remove comments and empty lines.
# Sort the list [numerically].
# Remove any duplicates.

# Turn "a:b //<NetFn>:<Command>" -> "{ a, b, NULL }, //<NetFn>:<Command>"
# Turn "a:b:c //<NetFn>:<Command>:<Channel>" -> "{ a, b, c }, //<NetFn>:<Command>:<Channel>"
cat $* | sed "s/#.*//" | sed '/^$/d' | sort -n | uniq | sed "s/^/    { /" | \
    while read line; \
    do if [[ $(echo $line | awk -F '0x' '{print NF-1}') -eq 2 ]]; \
        then echo $line | sed "s/\:\(....\)\(.*\)/ , \1 , NULL }, \2/"; \
        else echo $line | sed "s/\:\(....\)\:\(......\)\(.*\)/ , \1 , \2 }, \3/"; \
        fi; \
    done

cat << EOF
};
EOF
