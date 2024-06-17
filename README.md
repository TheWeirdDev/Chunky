# Chunky

Chunky is a lightweight http(s) proxy designed to circumvent censorship in countries where internet access is restricted. It works by chunking the TLS handshake and making it difficult for deep packet inspection (DPI) to detect and block the handshake.

## Configuration

Chunky has a few configuration options that can be set using command line arguments. The following options are available:

- `--host`: The host to listen on. Default: **127.0.0.1**
- `--port`: The port to listen on. Default: **8000**
- `-T` or `--dot-server`: The DNS-over-TLS server to use. Default: **1.1.1.1**
- `c` or `--chunk-size`: The size of each chunk in bytes. Default: **500**
- `-v` or `--verbose`: Enable verbose logging. Default: **Disabled**
- `-h` or `--help`: Display the help message

## How to run

To run Chunky, you need to have the Rust toolchain installed. You can install it by following the instructions [here](https://www.rust-lang.org/tools/install).

Once you have the Rust toolchain installed, you can run the following command to build and run Chunky:

```bash
cargo run --release
```

This will start the Chunky proxy on the default host and port mentioned above. You can then **configure your browser or system to use the proxy to access the internet**.

## Credits

- [DPYProxy](https://github.com/UPB-SysSec/DPYProxy)

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.
