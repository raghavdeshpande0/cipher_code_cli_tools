# Cryptography Study Toolkit (cipher_code_cli_tools)

A lightweight, interactive Command Line Interface (CLI) application written in Rust. This tool serves as an educational resource to explore, demonstrate, and test classic symmetric ciphers and foundational public-key cryptographic algorithms.

## Supported Ciphers & Protocols

*   **Vigenère Cipher:** A polyalphabetic substitution cipher that uses a keyword to shift letters dynamically through modular arithmetic, resisting simple frequency analysis.
*   **Rail Fence Transposition:** A form of transposition cipher that writes characters diagonally across a specified number of "rails" (rows) and reads them off row-by-row to scramble the plaintext.
*   **Columnar Transposition:** A transposition cipher where plaintext is written horizontally into a grid of a fixed width and then read out column-by-column in an order determined by an alphabetical keyword.
*   **Playfair Cipher:** A symmetric encryption technique that encrypts pairs of letters (digraphs) instead of single characters, using a 5x5 matrix generated from a keyword.
*   **Hill Cipher (2x2):** A polyalphabetic substitution cipher based on linear algebra. It treats blocks of text as vectors and encrypts them by performing matrix multiplication against an invertible 2x2 key matrix modulo 26.
*   **RSA Algorithm (Textbook):** A foundational asymmetric cryptographic algorithm. It demonstrates key generation (using primes $p$ and $q$), public/private key derivation, and modular exponentiation for encryption and decryption.
*   **Diffie-Hellman Key Exchange:** A protocol that allows two independent parties (Alice and Bob) to securely establish a shared secret key over an unsecure public channel using modular arithmetic.

---

## Prerequisites

To compile and run this project, you need to have the Rust toolchain (`rustup` and `cargo`) installed on your system.

### Installing Rust

If you do not have Rust installed, follow the instructions below based on your operating system:

#### Linux / macOS
Open your terminal and run the following command:
```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
```

#### For Windows
check this website https://rustup.rs/

## How to Run the Tool

### 1.Clone this repository to your local machine:
```
git clone https://github.com/raghavdeshpande0/cipher_code_cli_tools.git
cd cipher_code_cli_tools
```

### 2.Run the application directly using Cargo:
```
cargo run main.rs
```
The interactive menu will guide you through selecting a cipher, entering your plaintext, and defining the required keys.