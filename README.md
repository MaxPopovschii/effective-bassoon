A simple and extensible cryptography playground written in Go.

## Features

- **/crypto** endpoint for:
  - Base64 encode/decode
  - MD5 hash
  - SHA256 hash

## Usage

1. **Build and run the server:**
   ```sh
   go run main.go
   ```

2. **API Endpoints:**

   - **Base64 encode:**
     ```
     GET /crypto?algo=base64&action=encode&msg=yourtext
     ```
   - **Base64 decode:**
     ```
     GET /crypto?algo=base64&action=decode&msg=YmFzZTY0
     ```
   - **MD5 hash:**
     ```
     GET /crypto?algo=md5&msg=yourtext
     ```
   - **SHA256 hash:**
     ```
     GET /crypto?algo=sha256&msg=yourtext
     ```

3. **Example using curl:**
   ```sh
   curl "http://localhost/crypto?algo=sha256&msg=hello"
   ```

## Development

- All cryptography logic is in [`crypto_service.go`](crypto_service.go).
- The HTTP server is in [`main.go`](main.go).

## Requirements

- Go 1.20 or newer

## Open the web tester

If you have `web.html` in your project, you can open it with:
```sh
$BROWSER web.html
```

---

Feel free to extend this project with new algorithms or endpoints!