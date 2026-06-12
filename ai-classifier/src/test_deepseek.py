import asyncio
import aiohttp
import json
import os

from config import obtener_api_key

DEEPSEEK_API_KEY = obtener_api_key()

async def test_deepseek():
    url = "https://api.deepseek.com/chat/completions"
    payload = "GET /index.php?id=1' OR 1=1--"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Accept-Encoding": "gzip, deflate"
    }

    data = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "user",
                "content": payload
            }
        ],
        "temperature": 0.0
    }

    async with aiohttp.ClientSession() as session:
        print("Sending request to DeepSeek API with gzip accept-encoding...")
        try:
            async with session.post(url, headers=headers, json=data, timeout=30) as response:
                print(f"Status: {response.status}")
                if response.status >= 400:
                    text = await response.text()
                    print(f"Error Response: {text}")
                    return
                try:
                    result = await response.json()
                except Exception as e:
                    print(f"Failed to json(): {e}")
                    text = await response.text()
                    print(f"Raw Response: {text[:200]}")
                    return
                print(f"Result: {json.dumps(result, indent=2)[:200]}")
        except Exception as e:
            print(f"Request failed with Exception: {type(e).__name__} - {e}")

asyncio.run(test_deepseek())
