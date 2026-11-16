declare module "snarkjs" {
  export interface Groth16Proof {
    pi_a: [string, string, string];
    pi_b: [[string, string], [string, string], [string, string]];
    pi_c: [string, string, string];
    protocol: string;
    curve: string;
  }

  export interface FullProveResult {
    proof: Groth16Proof;
    publicSignals: string[];
  }

  export const groth16: {
    fullProve(
      input: Record<string, string | number | bigint | string[]>,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<FullProveResult>;
    verify(
      vkey: Record<string, unknown>,
      publicSignals: readonly string[],
      proof: Groth16Proof | Record<string, unknown>,
    ): Promise<boolean>;
  };
}
