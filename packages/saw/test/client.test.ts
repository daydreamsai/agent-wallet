import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createSawClient } from "../src/index";

type SawRequest = {
  request_id: string;
  action: string;
  wallet: string;
  payload?: unknown;
};

type SawResponse = {
  request_id: string;
  status: "approved" | "denied";
  result?: unknown;
  error?: string;
};

function makeSocketPath(): { dir: string; socketPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "saw-client-"));
  return { dir, socketPath: path.join(dir, "saw.sock") };
}

async function startServer(
  socketPath: string,
  handler: (request: SawRequest) => SawResponse
): Promise<{
  requests: SawRequest[];
  close: () => Promise<void>;
}> {
  const requests: SawRequest[] = [];

  const server = net.createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });
    socket.on("end", () => {
      const request = JSON.parse(data) as SawRequest;
      requests.push(request);
      const response = handler(request);
      socket.end(JSON.stringify(response));
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });

  return {
    requests,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

describe("createSawClient", () => {
  const env = { ...process.env };

  beforeEach(() => {
    process.env = { ...env };
  });

  afterEach(() => {
    process.env = env;
  });

  it("caches getAddress results", async () => {
    const { dir, socketPath } = makeSocketPath();
    const server = await startServer(socketPath, (request) => ({
      request_id: request.request_id,
      status: "approved",
      result: { address: "0xabc" },
    }));

    const client = createSawClient({ socketPath, wallet: "main" });
    const first = await client.getAddress();
    const second = await client.getAddress();

    expect(first).toBe("0xabc");
    expect(second).toBe("0xabc");
    expect(server.requests).toHaveLength(1);

    await server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("signs permit and returns signature", async () => {
    const { dir, socketPath } = makeSocketPath();
    const expectedPayload = {
      chain_id: 1,
      token: "0x1111111111111111111111111111111111111111",
      name: "USD Coin",
      version: "2",
      spender: "0x2222222222222222222222222222222222222222",
      value: "100",
      nonce: "0",
      deadline: "999",
      owner: "0xabc",
    };

    const server = await startServer(socketPath, (request) => ({
      request_id: request.request_id,
      status: "approved",
      result: { signature: "0xsig" },
    }));

    const client = createSawClient({ socketPath, wallet: "main" });
    const signature = await client.signEip2612Permit(expectedPayload);

    expect(signature).toBe("0xsig");
    expect(server.requests).toHaveLength(1);
    expect(server.requests[0]?.action).toBe("sign_eip2612_permit");
    expect(server.requests[0]?.wallet).toBe("main");
    expect(server.requests[0]?.payload).toEqual(expectedPayload);

    await server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("supports signEvmTx and signSolTx", async () => {
    const { dir, socketPath } = makeSocketPath();
    const responses: Record<string, SawResponse> = {
      sign_evm_tx: {
        request_id: "1",
        status: "approved",
        result: { raw_tx: "0xraw", tx_hash: "0xhash" },
      },
      sign_sol_tx: {
        request_id: "2",
        status: "approved",
        result: { signature: "sig", signed_tx_base64: "b64" },
      },
    };

    const server = await startServer(socketPath, (request) => ({
      ...responses[request.action],
      request_id: request.request_id,
    }));

    const client = createSawClient({ socketPath, wallet: "main" });

    const evm = await client.signEvmTx({
      chain_id: 1,
      nonce: 0,
      to: "0x1111111111111111111111111111111111111111",
      value: "0x0",
      gas_limit: 21000,
      max_fee_per_gas: "0x1",
      max_priority_fee_per_gas: "0x1",
      data: "0x",
    });
    const sol = await client.signSolTx({ message_base64: "aGVsbG8=" });

    expect(evm.raw_tx).toBe("0xraw");
    expect(sol.signature).toBe("sig");

    await server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("throws on denied response", async () => {
    const { dir, socketPath } = makeSocketPath();
    const server = await startServer(socketPath, (request) => ({
      request_id: request.request_id,
      status: "denied",
      error: "rate limit exceeded",
    }));

    const client = createSawClient({ socketPath, wallet: "main" });

    await expect(
      client.signEvmTx({
        chain_id: 1,
        nonce: 0,
        to: "0x1111111111111111111111111111111111111111",
        value: "0x0",
        gas_limit: 21000,
        max_fee_per_gas: "0x1",
        max_priority_fee_per_gas: "0x1",
        data: "0x",
      })
    ).rejects.toThrow("rate limit exceeded");

    await server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
