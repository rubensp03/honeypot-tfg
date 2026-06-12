import asyncio
import aiohttp
import json

async def test_deepseek_v4_pro():
    url = "https://api.deepseek.com/chat/completions"
    
    payload = "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1"
    
    prompt = (
        "Eres un analista experto en ciberseguridad. Analiza el siguiente payload HTTP. "
        "Devuelve ÚNICAMENTE un objeto JSON con: tipo_ataque, cve, gravedad, tecnologia_objetivo, explicacion.\n\n"
        f"Payload: {payload}"
    )
    
    from config import obtener_api_key
    api_key = obtener_api_key()
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    
    data = {
        "model": "deepseek-v4-pro",
        "messages": [
            {"role": "system", "content": "Responde únicamente con JSON válido."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0
    }
    
    async with aiohttp.ClientSession() as session:
        print("[*] Enviando petición a DeepSeek v4-pro...")
        async with session.post(url, headers=headers, json=data, timeout=60) as resp:
            print(f"[*] Status: {resp.status}")
            result = await resp.json()
            
            print("\n=== RESPUESTA COMPLETA ===")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
            msg = result["choices"][0]["message"]
            content = msg.get("content", "")
            reasoning = msg.get("reasoning_content", "")
            
            print("\n=== CONTENT ===")
            print(content)
            print("\n=== REASONING ===")
            print(reasoning[:500] if reasoning else "(No reasoning returned)")

if __name__ == "__main__":
    asyncio.run(test_deepseek_v4_pro())
