# cloakimg

A command-line tool for hiding and extracting UTF-8 text in images using RGB LSB steganography.

## Features

- **Encode text into images**: Uses least significant bits of RGB channels.
- **Decode embedded text**: Recover hidden messages from compatible images.
- **File or inline input**: Provide text directly or from a UTF-8 text file.
- **Optional ChaCha20 encryption**: Store a key/nonce pair in files to encrypt data before embedding.
- **Safe error handling**: Clear error messages and non-zero exit codes on failure.

## Usage

 The tool is driven by subcommands:

- **`encode`**: Embed text into a file.
- **`decode`**: Extract text from a file.

 Run the following to see the built-in help:

 ```bash
 cloakimg --help
 ```

## Examples

- **Hide a short note**:

 ```bash
 cloakimg encode data/tp0n3p08.png data/tp0n3p08_secret.png -i "Meet at 19:30."
 ```

- **Embed the source code into a image**:

 ```bash
 cloakimg encode data/tp0n3p08.png data/tp0n3p08_source.png --file src/stego/encode.rs"
 ```

- **Recover a message to the terminal**:

 ```bash
 cloakimg decode data/tp0n3p08_secret.png
 ```

- **Recover a message to a file**:

 ```bash
 cloakimg decode data/with_payload.png --output recovered.txt
 ```

## Encryption

Enable authenticated callers to encrypt the payload before embedding by providing file paths that contain a ChaCha20 key and nonce. Each file can hold either raw bytes (32 bytes for the key, 12 for the nonce) or an ASCII hex string. You may optionally adjust the initial block counter (defaults to `0`).

```bash
# Encrypt before embedding
cloakimg encode data/tp0n3p08.png data/tp0n3p08_secret.png \
  --key-file secrets/chacha20.key \
  --nonce-file secrets/chacha20.nonce \
  --counter 1 \
  -i "Meet at 19:30."

# Provide the same parameters to decrypt
cloakimg decode data/tp0n3p08_secret.png \
  --key-file secrets/chacha20.key \
  --nonce-file secrets/chacha20.nonce
```

Mismatched keys, nonces, or counters will prevent successful decryption. Ensure each nonce is unique per key.

## Limitations

- Supported image formats: PNG, BMP, TIFF, PPM.
- Available capacity depends on image dimensions and encoding details; very long messages may not fit into small images.
- The tool expects valid UTF-8 text for both input and output.
