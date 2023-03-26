# HTTPS Proxy Server Sample


```powershell
PS > $cred = Get-Credential -UserName user -Message pass
PS > Invoke-WebRequest https://example.com -Proxy http://127.0.0.1:18080 -ProxyCredential $cred
```