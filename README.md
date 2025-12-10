# cloakimg

> [!CAUTION]  
> This tool is not audited for security.
>
> It is not recommended for production use.
>
> It is not recommended for use in critical systems.

A command-line tool for hiding and extracting UTF-8 text/binary data in images using RGB LSB steganography.

## Features

- **Encode text/binary data into images**: Uses least significant bits of RGB channels.
- **Decode embedded data**: Recover hidden messages from compatible images.
- **File or inline input**: Provide data directly or from a file.
- **Optional encryption**: Store a key/nonce pair in files to encrypt data before embedding.
- **Safe error handling**: Clear error messages and non-zero exit codes on failure.

## Usage

 The tool is driven by subcommands:

- **`encode`**: Embed data into a file.
- **`decode`**: Extract data from a file.
- **`cap`**: Calculate the maximum possible payload size for an image.

 Run the following to see the built-in help:

 ```bash
 cloakimg --help
 ```

## Examples

- **Hide a short note**:

 ```bash
 cloakimg encode data/tp0n3p08.png -t "Meet at 19:30." # output is "a.png"
 ```

- **Embed the source code into a image**:

 ```bash
 cloakimg encode data/tp0n3p08.png --file src/stego/encode.rs"
 ```

- **Recover a message to the terminal**:

 ```bash
 cloakimg decode data/tp0n3p08_secret.png
 ```

- **Recover a message to a file**:

 ```bash
 cloakimg decode data/with_payload.png --output recovered.txt
 ```

## Encryption (Optional)

Enable authenticated callers to encrypt the payload before embedding by providing a key file. The key file can hold either raw bytes (32 bytes) or an ASCII hex string.

A fresh nonce is generated for each encryption and automatically embedded in the payload. The format is: `[12-byte nonce][N-byte ciphertext][16-byte tag]`. During decryption, the nonce is extracted automatically.

```bash
# Encrypt before embedding
cloakimg encode data/tp0n3p08.png -o data/tp0n3p08_secret.png \
  --key-file secrets/image.key \
  -t "Meet at 19:30."

# Provide the same key to decrypt (nonce is extracted automatically)
cloakimg decode data/tp0n3p08_secret.png \
  --key-file secrets/image.key
```

Mismatched keys will prevent successful decryption. Each encryption automatically uses a unique nonce.

## Limitations

- Supported image formats: PNG, BMP, TIFF, PPM.
- Available capacity depends on image dimensions and encoding details; very long messages may not fit into small images.
