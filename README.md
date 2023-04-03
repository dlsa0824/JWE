# JWE
JWE with A128CBC-HS256 and RSA-OAEP-256
Format is General JWE JSON Serialization


---
### Example Format
all value are encoded with BASE64URL
```json
{
  "ciphertext": "cwFv6MEURd_Wl4teKMMlJKQY8GbSNk4jWnKg2TCzBgM",
  "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0",
  "recipients": [
    {
      "encrypted_key": "LT7e7ED1f-TFyJnrYhs9nXhpLSBmV94wWKMu4_6CWGS0mTE87vqL7_ZYkxC4DB4R6FIn8c4PJ5ADRONwsfoRTAj_8Iib5q8HUb56zTOWmo30nJAnlWWbvQ25qMLETf2iDTQJIgTC5oExepdDAtYCl8iiAL9NBledV6cgk2M9BDIhJ3CCvWJHy_m21sA97OQK05O-WKkBCJ6lj4Mz3pEu6uc6riDi9ukAZj1KpyuXTO8zRIrwECKI2S5UozMW5NN2xdibjbfYKkBMWC38c03G0xsTngHs_FiaQpP13bKoXgiBHJ1Z42-5_ldEdzeDYcW5KdVcPNi0GX6F8pNPdnOQSw"
    }
  ],
  "tag": "nqvcXb8yVYmRQpHt-WoUHA",
  "iv": "-3iO8Al05UF7ZkdcgOJYDw"
}
```
---
###Parameter
rsa algorithm : RSA/ECB/OAEPWithSHA-256AndMGF1Padding
aes algorithm : AES/CBC/PKCS5Padding
hash algorithm : HmacSHA256

---
###Encrypt Steps
1. 外部檔案載入RSA公鑰(cer)
2. 隨機產生256bit, 32byte CEK密鑰
3. 將32byte CEK密鑰拆分 > 前16byte為hmac密鑰, 後16byte為AES密鑰
4. 隨機產生16byte iv
5. 組成jwe protected header (enc: A128CBC-HS256, alg: RSA-OAEP-256)
6. RSA私鑰對CEK密鑰進行加密 (需使用外部Provider, 例如Bouncy Castle, 因預設的 MGF1 採用 SHA-1) -> encrypted key
7. AES密鑰對明文進行加密 (須帶入iv) > ciphertext
8. 產生驗證tag
	1. 對BASE64URL(protected header)做ASCII編碼 > AAD
	2. 對AAD Length做64-Bit Big-Endian Representation > octets
	3. 串接 (AAD + iv + ciphertext + octets)
	4. 對串接後data做HMAC256計算 > hmac data
	5. 取hmac data的前16byte做為tag值
9. 組成JWE json格式
	1. BASE64URL(protected header)
	2. BASE64URL(encrypted key)
	3. BASE64URL(ciphertext)
	4. BASE64URL(iv)
	5. BASE64URL(tag)

---
###Decrypt Steps
1. 外部檔案載入RSA私鑰(pfx)
2. 對全部欄位BASE64URL deocde
3. RSA私鑰對CEK密鑰進行解密
4. 將解密的CEK拆分 > 前16byte為hmac密鑰, 後16byte為AES密鑰
5. 產生驗證tag (產生方式如上方)
6. 比對tag是否一致
7. AES密鑰對密文進行解密 -> plaintext