# Crypto-js-for-csharp

Link original do artigo:
https://truongtx.me/2021/08/14/port-crypto-js-aes-functions-to-csharp

crypto-js - npm install
https://www.npmjs.com/package/crypto-js

Front:
const cryptojs = require('crypto-js');
const encryptedMsg = cryptojs.AES.encrypt('message', 'secret').toString();

resultado será semelhando a o gerado:
U2FsdGVkX184KJolbrZkg8w+rX/V9OW7sbUvWPVogdY=

No C# é so usar method DecryptAes para descriptrografar a senha gerada pelo o front. 

Pendente criação do código de criptrografia do lado do Back end. 
