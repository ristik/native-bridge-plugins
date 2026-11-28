# ERC20 NB2 signed vectors

`generator.json` pins the Go oracle commit, command, output variable and
exact SHA-256. From that checkout, set the variable to a temporary output
file, run the command, and compare the result byte for byte to
`vectors.json`. The vector fixture uses synthetic factory templates and
verifier graph addresses. The contract suite measures actual compiled
templates separately.

`sdk-deployment.json.gz` records the Anvil deployment made by the contracts
commit in `generator.json`. Run the contracts README's test and production
build commands, then run `script/nb2-erc20/measure-activation.py --sdk-root`
with the fixture trust pin from `generator.json`. The fixture holds the
deployed runtime code, both vault configs and the batched activation logs.
The SDK tests build and certify receipts over those logs with fixture
authorities, then verify them through the production-profile open path.

The assets include two token addresses on one execution genesis and the
first token address on a second genesis with the same chain ID. Each
fixture contains a certified net-credit origin, a split, a held child,
its exact terminal verdict and a recovery packet and Complete proof.
