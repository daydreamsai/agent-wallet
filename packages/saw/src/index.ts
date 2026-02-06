import net from "node:net";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";

export type SawClientOptions = {
  socketPath?: string;
  wallet?: string;
};

export type SawRequest = {
  request_id: string;
  action: string;
  wallet: string;
  payload?: unknown;
};

export type SawResponse<T = unknown> = {
  request_id: string;
  status: "approved" | "denied";
  result?: T;
  error?: string;
};

export type EvmTxPayload = {
  chain_id: number;
  nonce: number;
  to: string;
  value: string;
  gas_limit: number;
  max_fee_per_gas: string;
  max_priority_fee_per_gas: string;
  data: string;
};

export type SolTxPayload = {
  message_base64: string;
};

export type Eip2612PermitPayload = {
  chain_id: number;
  token: string;
  name: string;
  version: string;
  spender: string;
  value: string;
  nonce: string;
  deadline: string;
  owner?: string;
};

export type SignEvmTxResult = {
  raw_tx: string;
  tx_hash: string;
};

export type SignSolTxResult = {
  signature: string;
  signed_tx_base64: string;
};

export type SignPermitResult = {
  signature: string;
};

export type AddressResult = {
  address: string;
  public_key?: string;
  chain?: string;
};

async function sendRequest(socketPath: string, request: SawRequest): Promise<SawResponse> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath);
    let data = "";

    client.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });

    client.on("end", () => {
      try {
        resolve(JSON.parse(data) as SawResponse);
      } catch (err) {
        reject(err);
      }
    });

    client.on("error", reject);

    client.write(JSON.stringify(request));
    client.end();
  });
}

export function createSawClient(options: SawClientOptions = {}) {
  const socketPath = options.socketPath ?? process.env.SAW_SOCKET ?? path.join(os.homedir(), ".saw", "saw.sock");
  const wallet = options.wallet ?? process.env.SAW_WALLET ?? "main";
  let cachedAddress: string | null = null;

  async function request<T>(action: string, payload?: unknown): Promise<T> {
    const res = await sendRequest(socketPath, {
      request_id: crypto.randomUUID(),
      action,
      wallet,
      payload,
    });

    if (res.status !== "approved") {
      throw new Error(res.error || "saw denied");
    }

    return res.result as T;
  }

  return {
    async getAddress(): Promise<string> {
      if (!cachedAddress) {
        const result = await request<AddressResult>("get_address");
        cachedAddress = result.address;
      }
      return cachedAddress;
    },

    async signEvmTx(payload: EvmTxPayload): Promise<SignEvmTxResult> {
      return request<SignEvmTxResult>("sign_evm_tx", payload);
    },

    async signSolTx(payload: SolTxPayload): Promise<SignSolTxResult> {
      return request<SignSolTxResult>("sign_sol_tx", payload);
    },

    async signEip2612Permit(payload: Eip2612PermitPayload): Promise<string> {
      const result = await request<SignPermitResult>("sign_eip2612_permit", payload);
      return result.signature;
    },
  };
}
