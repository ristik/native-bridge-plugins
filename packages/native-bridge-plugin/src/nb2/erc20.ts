import { HE } from './crypto.js';

/** A release pins the factory and templates. The locator can come from any activator. */
export interface Erc20ActivationPins {
  factory: Uint8Array;
  factoryRuntimeHash: Uint8Array;
  vaultInitcodeHash: Uint8Array;
  recoveryInitcodeHash: Uint8Array;
  activationTx: Uint8Array;
  fundingQualified?: boolean;
}

export const ERC20_DEPOSIT_RISKS =
  'Outbound taxes, rebases, confiscation and token upgrades can prevent redemption. Token metadata is display only.';
export const ERC20_RETURN_RISKS =
  'The burn fixes this recipient. A permanent block or outbound tax can strand the claim. Anyone can retry the same signed burn to this recipient.';

export function erc20Create2(factory: Uint8Array, salt: Uint8Array, initcodeHash: Uint8Array): Uint8Array {
  return HE(Uint8Array.of(0xff), factory, salt, initcodeHash).slice(12);
}
