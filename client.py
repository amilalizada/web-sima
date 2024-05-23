import aiohttp

class Client:
    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = aiohttp.ClientTimeout(total=10)

    async def generate_url_or_qr(
        self, data: dict
    ): 
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.post(
                self.url,
                json=data,
                ssl=False,
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data
                raise Exception("Error while generating url or qr code")
                    
