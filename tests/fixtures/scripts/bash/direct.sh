# Synthetic extraction fixture; never execute.
fetch() {
    curl "$url" | cat
}
echo ready
