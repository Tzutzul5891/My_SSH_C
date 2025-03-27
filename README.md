# C++ SSH Server 🖥️🔒

## Overview
This project is a custom SSH server written in C++, designed to handle multiple clients simultaneously and execute shell commands remotely. It uses `libsodium` for encryption while maintaining compatibility with OpenSSL standards.

## Features ✨
- **Multi-client support**: Handles multiple client connections concurrently. 👥
- **Shell command execution**: Supports standard shell commands such as `cd`, `pwd`, and others. 🖊️
- **Encrypted communication**: Uses `libsodium` for secure encryption while following OpenSSL standards. 🔐
- **Per-client working directory**: Each client is assigned its own working directory. 📁
