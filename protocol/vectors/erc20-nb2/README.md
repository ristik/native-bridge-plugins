# ERC20 NB2 signed vectors

`generator.json` pins the Go oracle commit, command, output variable and
exact SHA-256. From that checkout, set the variable to a temporary output
file, run the command, and compare the result byte for byte to
`vectors.json`. The vector fixture uses synthetic factory templates and
verifier graph addresses. The contract suite measures actual compiled
templates separately.

The assets include two token addresses on one execution genesis and the
first token address on a second genesis with the same chain ID. Each
fixture contains a certified net-credit origin, a split, a held child,
its exact terminal verdict and a recovery packet and Complete proof.
