# Simplification of TLS 1.3 Handshake

TLS 1.3 has simplified the handshake process compared to TLS 1.2. While this enhancement improves performance, it also raises some security concerns.

## TLS Handshake Process Comparison

### TLS 1.2 Handshake Process
The TLS 1.2 handshake involves six steps:
1. **ClientHello**
2. **ServerHello**
3. **Server Key Exchange**
4. **Client Key Exchange**
5. **Change Cipher Spec**
6. **Finished**
- **TLS 1.2**: Requires **3 steps** to transmit the client's public key.

### TLS 1.3 Handshake Process
The TLS 1.3 handshake is simplified to three steps:
1. **ClientHello**
2. **ServerHello**
3. **Finished**
- **TLS 1.3**: The client’s public key is transmitted in just **1 step**.

## Security Concerns
The simplified handshake structure of TLS 1.3 can increase vulnerability to **SSL/TLS flood attacks**.  
Attackers can execute SSL/TLS attacks more quickly and easily due to the reduced handshake overhead.

---

## License

MIT License

Copyright (c) [YEAR] [YOUR NAME OR ORGANIZATION]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
