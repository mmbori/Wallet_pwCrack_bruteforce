## Prerequisites

The following dependencies should be installed to use this project.

## Sparrow

### ODBC Driver

- **Version**: 9.0 (psqlodbc_09_00_0101-x64)
- **Download**: [PostgreSQL ODBC driver](https://www.postgresql.org/ftp/odbc/versions/msi/)

### H2DB

- **Version**: 2.1.214
- **Note**: Ensure `h2-2.1.214.jar` is placed in the same path as the source code. For using the newest version, you might need to edit `server.bat`.
- **Download**: [H2DB](https://www.h2database.com/html/download.html)

### Vcpkg

- **Instructions**:
  - Install OpenSSL and Argon2 using vcpkg:
    ```
    vcpkg install openssl
    vcpkg install argon2
    ```
  - Integrate vcpkg with your development environment:
    ```
    vcpkg integrate install
    ```

## Etherwall

- **Instructions**:
  - Install libsodium and cryptopp using vcpkg:
    ```
    vcpkg install libsodium:x64-windows
    vcpkg install cryptopp:x64-windows
    ```
  - Integrate vcpkg with your development environment:
    ```
    vcpkg integrate install
    ```

  ## Bither

- **Instructions**:
  - Install openssl and sqlite3 using vcpkg:
    ```
    vcpkg install openssl:x64-windows
    vcpkg install sqlite3:x64-windows
    ```
  - Integrate vcpkg with your development environment:
    ```
    vcpkg integrate install
    ```

