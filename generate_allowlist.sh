#/bin/sh

# Ensure some files have been passed.
if [ "x$*" == "x" ]; then
    echo "Usage: $0 [allowlist_files+]" >&2
    exit -1
fi

cat << EOF
#include <ipmiallowlist.hpp>

const std::vector<netfncmd_pair> allowlist = {

EOF

# Output each row of allowlist vector.
# Concatenate all the passed files.
# Remove comments and empty lines.
# Sort the list [numerically].
# Remove any duplicates.
# Turn "a:b //<NetFn>:<Command>" -> "{ a, b }, //<NetFn>:<Command>"
cat $* | sed "s/#.*//" | sed '/^$/d' | sort -n | uniq | sed "s/^/    { /" | \
    sed "s/\:\(....\)\(.*\)/ , \1 }, \2/"

cat << EOF
};
EOF
