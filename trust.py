import asyncio
import aiohttp
import secrets
from mnemonic import Mnemonic
from eth_account import Account

Account.enable_unaudited_hdwallet_features()
MNEMO = Mnemonic("english")

CHAINS = {
    "ETH": {
        "rpcs": [
            "https://eth.llamarpc.com",
            "https://rpc.ankr.com/eth"
        ],
        "decimals": 18
    },
    "BSC": {
        "rpcs": [
            "https://bsc-dataseed1.binance.org",
            "https://rpc.ankr.com/bsc"
        ],
        "decimals": 18
    }
}

DERIVATION_PATH = "m/44'/60'/0'/0/0"


class SilentScanner:
    def __init__(self, concurrency=50):
        self.sem = asyncio.Semaphore(concurrency)
        self.rpc_index = {c: 0 for c in CHAINS}
        self.session = None

    def rpc(self, chain):
        rpcs = CHAINS[chain]["rpcs"]
        i = self.rpc_index[chain] % len(rpcs)
        self.rpc_index[chain] += 1
        return rpcs[i]

    async def start(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=3)
        )

    async def close(self):
        await self.session.close()

    def gen_wallet(self):
        mnemonic = MNEMO.to_mnemonic(secrets.token_bytes(32))
        acct = Account.from_mnemonic(mnemonic, account_path=DERIVATION_PATH)
        return mnemonic, acct.address

    async def balance(self, address, chain):
        async with self.sem:
            try:
                payload = {
                    "jsonrpc": "2.0",
                    "method": "eth_getBalance",
                    "params": [address, "latest"],
                    "id": 1
                }
                async with self.session.post(self.rpc(chain), json=payload) as r:
                    data = await r.json()
                    return int(data["result"], 16) / 10**CHAINS[chain]["decimals"]
            except:
                return 0.0

    async def check_wallet(self):
        mnemonic, address = self.gen_wallet()
        tasks = [self.balance(address, c) for c in CHAINS]
        balances = await asyncio.gather(*tasks)

        if any(b > 0 for b in balances):
            print("\n🔥🔥🔥 FOUND WALLET 🔥🔥🔥")
            print("ADDRESS :", address)
            print("MNEMONIC:", mnemonic)
            for c, b in zip(CHAINS, balances):
                print(f"{c}: {b:.8f}")
            print("=" * 60)

    async def run(self, batch=20):
        await self.start()
        try:
            while True:
                await asyncio.gather(*(self.check_wallet() for _ in range(batch)))
        finally:
            await self.close()


async def main():
    scanner = SilentScanner(concurrency=50)
    await scanner.run(batch=20)

if __name__ == "__main__":
    asyncio.run(main())
