/**
 * The reference command-line wallet of native bridge v2 (bft-core#1107): one command per bridge step, on the TypeScript plug-in, through a
 * deployment's public gateway only. docs/nb2-wallet-guide.md walks through it. A test wallet: its secret is unencrypted on disk.
 *
 *   npx tsx wallet/nb2-wallet.ts [--wallet DIR] COMMAND ...      (DIR defaults to ./nb2-wallet)
 *
 *   init --release FILE --rpc URL [--aggregator URL] [--trust-bundle FILE] [--trust-pin FILE] [--key-env NAME]
 *                              a new wallet for the deployment in FILE (nb2-release.json); the installation check; prints the EVM address to fund
 *   address                    the EVM address, its balance, and the wallet's Unicity owner key
 *   deposit NAME AMOUNT        plan a deposit of AMOUNT UCT (the secret and its backup first), then send it to the vault; again with
 *                              NAME (AMOUNT optional) it reconciles the planned deposit and never sends a second one
 *   mint NAME                  wait for the deposit block's certificate, build the receipt proof and mint the token NAME
 *   transfer NAME NEW [--to-key KEY]   an ordinary Unicity transfer (to the wallet's next own key, or to another wallet's key)
 *   split NAME NEW=AMOUNT NEW=AMOUNT ...   split NAME into whole parts
 *   plan-return NAME [--recipient ADDR]    the capacity preflight of returning NAME to ADDR (default: the wallet's address); burns nothing
 *   burn NAME [--recipient ADDR]           preflight again on fresh state, then burn NAME for ADDR (irreversible)
 *   redeem NAME                build the witness from the chain, send the redeem transaction, wait for the payment
 *   tokens [--all]             the tokens the wallet holds (--all: also the spent ones)
 *   status                     where every deposit, transfer and return stands, and what to run next
 *
 * Every command but address, tokens and status runs the installation check first, and one process at a time uses a wallet (its lock file).
 */
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';

import { keccak_256 } from '@noble/hashes/sha3.js';

import { Nb2Error, WalletError } from '../packages/native-bridge-plugin/src/nb2/index.js';
import {
  RegistryLagExpired, Wallet, burn, connectionOf, hx, mint, parseAmount, planDeposit, planReturn, redeem, sendDeposit, split, status, transfer, uct, unhex,
  type WalletConfig,
} from './core.js';

const formatAmount = (wei: bigint | string): string => `${uct(wei)} UCT`;
const say = (s: string): void => console.log(s);
const retrying = (what: string) => (reason: string): void => say(`  ${what}: ${reason}, retrying`);

function option(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith('--')) throw new Error(`${name} needs a value`);
  args.splice(i, 2);
  return v;
}

function flag(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i >= 0) args.splice(i, 1);
  return i >= 0;
}

function need(args: string[], n: number, usage: string): void {
  if (args.length < n) throw new Error(`usage: ${usage}`);
}

/** An EVM address: 20 bytes of hex; a mixed-case one must carry its EIP-55 checksum. */
function address(s: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) throw new Error(`not an EVM address: ${s}`);
  const body = s.slice(2);
  if (body !== body.toLowerCase() && body !== body.toUpperCase()) {
    const h = Buffer.from(keccak_256(new TextEncoder().encode(body.toLowerCase()))).toString('hex');
    const sum = [...body.toLowerCase()].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
    if (sum !== body) throw new Error(`${s} fails its EIP-55 checksum: check the address`);
  }
  return unhex(s);
}

async function init(dir: string, args: string[]): Promise<void> {
  const release = option(args, '--release');
  const rpc = option(args, '--rpc');
  if (!release || !rpc) throw new Error('usage: init --release FILE --rpc URL [--aggregator URL] [--trust-bundle FILE] [--trust-pin FILE] [--key-env NAME]');
  const keyEnv = option(args, '--key-env');
  const cfg: WalletConfig = { ...connectionOf({ release, rpc, aggregator: option(args, '--aggregator'), trustBundle: option(args, '--trust-bundle'), trustPin: option(args, '--trust-pin') }), ...(keyEnv ? { keyEnv } : {}) };
  // the installation check (the chain ID, config() against the pinned Γ, the vault's runtime code hash) passes before anything is written
  const w = await Wallet.create(dir, cfg, () => Uint8Array.from(randomBytes(32)));
  say(`wallet ${resolve(dir)} for the ${w.pins.build} vault ${hx(w.bridge.cfg.vault)} on chain ${w.bridge.cfg.chainId}`);
  say(`installation check passed: chain ID, config() = the pinned Γ, the vault's runtime code hash`);
  say(`fund this EVM address with UCT for deposits and gas: ${hx(w.signer.address)}`);
}

/** The commands that read only: every other one runs the installation check first. */
const READ_ONLY = new Set(['address', 'tokens', 'status']);

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dir = option(args, '--wallet') ?? 'nb2-wallet';
  const [cmd, ...rest] = args;
  if (cmd === 'init') return init(dir, rest);
  const recipientOpt = option(rest, '--recipient');
  const toKeyOpt = option(rest, '--to-key');
  const all = flag(rest, '--all');
  const recipient = recipientOpt ? address(recipientOpt) : undefined;
  // a command that moves value checks the deployment again first: a network reset can leave the same chain ID and vault address with
  // another vault behind them, and the saved manifest is then not that deployment's
  const w = await Wallet.load(dir).open({ check: !READ_ONLY.has(cmd) });
  switch (cmd) {
    case 'address': {
      say(`EVM address ${hx(w.signer.address)}: ${formatAmount(await w.bridge.evm.balance(w.signer.address))}`);
      say(`Unicity owner key ${hx(w.ownerPub(0))}`);
      return;
    }
    case 'deposit': {
      need(rest, 1, 'deposit NAME AMOUNT');
      const [name, amount] = rest;
      if (!w.has(name)) {
        need(rest, 2, 'deposit NAME AMOUNT');
        const plan = await planDeposit(w, name, parseAmount(amount));
        say(`planned deposit intent ${plan.intent} of ${formatAmount(plan.amount)} as ${name}; the intent high-water mark is backed up`);
      } else {
        // a deposit already planned under NAME is only reconciled (submitDeposit never sends it twice), and only for its own amount
        const e = w.entry(name);
        if (e.intent === undefined) throw new Error(`the wallet already has a token named ${name}`);
        if (amount !== undefined && parseAmount(amount) !== BigInt(e.amount)) throw new Error(`${name} is a planned deposit of ${formatAmount(e.amount)}, not ${amount}: run deposit ${name} ${uct(e.amount)}`);
      }
      const r = await sendDeposit(w, name);
      say(`deposit ${r.depositNumber} in block ${r.blockNumber} (tx ${hx(r.txHash)})`);
      say(`next: mint ${name}`);
      return;
    }
    case 'mint': {
      need(rest, 1, 'mint NAME');
      const m = await mint(w, rest[0], retrying('the deposit proof'));
      say(`minted ${rest[0]}: ${formatAmount(m.amount)} from deposit ${m.depositNumber}, token ${hx(m.tokenId).slice(0, 18)}.., J ${m.reasonBytes} bytes`);
      return;
    }
    case 'transfer': {
      need(rest, 2, 'transfer NAME NEW [--to-key KEY]');
      const own = (w.entry(rest[0]).owner + 1) % 4;
      await transfer(w, rest[0], rest[1], own, toKeyOpt ? unhex(toKeyOpt) : undefined);
      if (toKeyOpt) say(`transferred ${rest[0]} to ${toKeyOpt}: hand ${resolve(w.dir, 'tokens', `${rest[1]}.cbor`)} to its owner`);
      else say(`transferred ${rest[0]} as ${rest[1]} to the wallet's owner key ${own}`);
      return;
    }
    case 'split': {
      need(rest, 3, 'split NAME NEW=AMOUNT NEW=AMOUNT ...');
      const parts = rest.slice(1).map((s) => {
        const [label, amount] = s.split('=');
        if (!label || !amount) throw new Error(`a part is NEW=AMOUNT: ${s}`);
        return { label, amount: parseAmount(amount) };
      });
      await split(w, rest[0], w.entry(rest[0]).owner, parts);
      say(`split ${rest[0]} into ${parts.map((p) => `${p.label} (${formatAmount(p.amount)})`).join(' + ')}`);
      return;
    }
    case 'plan-return': {
      need(rest, 1, 'plan-return NAME [--recipient ADDR]');
      const p = await planReturn(w, rest[0], recipient, retrying('the seal receipt'));
      say(`the preflight passes: ${rest[0]} (${formatAmount(p.amount)}) to ${hx(p.recipient)} at index a = ${p.a}, vault at segment ${p.cObs}`);
      say(`  gas limit ${p.gasLimit} of userGasLimit ${w.pins.userGasLimit}; room for ${p.pMax} historical proofs, ${p.marginSegments} beyond the reserve`);
      for (const x of p.warnings) say(`  warning: ${x}`);
      say(`nothing is burned. Run burn ${rest[0]} to return it: the preflight runs again on fresh state first`);
      return;
    }
    case 'burn': {
      need(rest, 1, 'burn NAME [--recipient ADDR]');
      const b = await burn(w, rest[0], recipient, retrying('the burn'));
      if (b.plan === null) say(`${rest[0]} was already burned: resumed`);
      else say(`the preflight passes again: gas limit ${b.plan.gasLimit}, index a = ${b.plan.a}`);
      const rec = await w.returnRecord(rest[0]);
      say(`burned ${rest[0]} for ${rec.recipient}: ${formatAmount(rec.amount)}, redemption ID ${hx(b.eta).slice(0, 18)}.., ${b.evidenceBytes} evidence bytes`);
      say(`next: redeem ${rest[0]}`);
      return;
    }
    case 'redeem': {
      need(rest, 1, 'redeem NAME');
      const r = await redeem(w, rest[0], 60, 3_000, (why) => say(`  ${why}; waiting`));
      const rec = await w.returnRecord(rest[0]);
      if (r.state === 'paid') say(`paid ${formatAmount(rec.amount)} to ${rec.recipient} in block ${r.blockNumber} (tx ${hx(r.txHash)}); ${rec.sends.length} redeem transaction${rec.sends.length === 1 ? '' : 's'} sent`);
      else if (r.state === 'pending') say(`sent (tx ${hx(r.txHash)}), not certified yet: run redeem ${rest[0]} again to reconcile`);
      else throw new Error(`${rest[0]} is not paid${r.lastFailure ? `: ${r.lastFailure.action}, ${r.lastFailure.error?.rule ?? 'no revert data'}` : ''}. The burn is intact; see status`);
      return;
    }
    case 'tokens': {
      // the tokens the wallet holds; --all also lists the spent ones (split, transferred, sent, burned) and deposits not minted yet
      for (const l of w.labels()) {
        const e = w.entry(l);
        const minted = w.token(l).length > 0;
        if (!all && (e.spent || !minted)) continue;
        say(`${l}: ${formatAmount(e.amount)}${e.spent ? ` (spent: ${e.spent})` : !minted ? ' (deposit, not minted)' : ''}`);
      }
      return;
    }
    case 'status': {
      for (const line of await status(w)) say(line);
      return;
    }
    default:
      throw new Error(`unknown command ${cmd ?? '(none)'}: init, address, deposit, mint, transfer, split, plan-return, burn, redeem, tokens, status`);
  }
}

main().catch((e) => {
  if (e instanceof RegistryLagExpired) {
    console.error(`not paid yet: ${e.message}`);
    process.exit(1);
  }
  console.error(e instanceof Nb2Error ? `refused: ${e.rule}: ${e.message}` : e instanceof WalletError ? `refused: ${e.reason}: ${e.message}` : `error: ${(e as Error).message ?? e}`);
  process.exit(1);
});
