export class WalletAbiSdkValidationError extends Error {
  readonly issues: string[];

  constructor(message: string, issues: string[] = []) {
    super(message);
    this.name = "WalletAbiSdkValidationError";
    this.issues = issues;
  }
}
