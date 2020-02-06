#if SQLITE_SWIFT_SQLCIPHER
import SQLCipher


/// Extension methods for [SQLCipher](https://www.zetetic.net/sqlcipher/).
/// @see [sqlcipher api](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
extension Connection {

    /// - Returns: the SQLCipher version
    public var cipherVersion: String? {
        return (try? scalar("PRAGMA cipher_version")) as? String
    }

    /// Specify the key for an encrypted database.  This routine should be
    /// called right after sqlite3_open().
    ///
    /// @param key The key to use.The key itself can be a passphrase, which is converted to a key
    ///            using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) key derivation. The result
    ///            is used as the encryption key for the database.
    ///
    ///            Alternatively, it is possible to specify an exact byte sequence using a blob literal.
    ///            With this method, it is the calling application's responsibility to ensure that the data
    ///            provided contains 32 bytes (256 bits) of key data, or 48 bytes (384 bits) if it includes the salt as well.
    /// @param db name of the database, defaults to 'main'
    public func key(_ key: String, db: String = "main") throws {
        try _key_v2(db: db, keyPointer: key, keySize: key.utf8.count)
    }

    public func key(_ key: Blob, db: String = "main") throws {
        try key.description.utf8CString.withUnsafeBytes { (ptr) in
            let bound = ptr.bindMemory(to: UInt8.self)
            try _key_v2(db: db, keyPointer: bound.baseAddress!, keySize: bound.count - 1)
        }
    }
    
    public func key(_ key: ContiguousBytes, db: String = "main") throws {
        try key.withUnsafeBytes { ptr in
            var chars = [UInt8]()
            chars += "x'".utf8CString.dropLast().map { UInt8($0) }
            for byte in ptr {
                if byte < 16 {
                    chars += "0".utf8CString.dropLast().map { UInt8($0) }
                }
                chars += String(byte, radix: 16, uppercase: false).utf8CString.dropLast().map { UInt8($0) }
            }
            chars += "'".utf8CString.dropLast().map { UInt8($0) }
            try chars.withUnsafeBufferPointer { ptr in
                try _key_v2(db: db, keyPointer: ptr.baseAddress!, keySize: ptr.count)
            }
            let errno = chars.withUnsafeMutableBytes { ptr in
                memset_s(ptr.baseAddress!, ptr.count, 0, ptr.count)
            }
            guard errno == 0 else {
                throw NSError(domain: POSIXError.errorDomain, code: Int(errno))
            }
        }
    }


    /// Change the key on an open database.  If the current database is not encrypted, this routine
    /// will encrypt it.
    /// To change the key on an existing encrypted database, it must first be unlocked with the
    /// current encryption key. Once the database is readable and writeable, rekey can be used
    /// to re-encrypt every page in the database with a new key.
    public func rekey(_ key: String, db: String = "main") throws {
        try _rekey_v2(db: db, keyPointer: key, keySize: key.utf8.count)
    }

    public func rekey(_ key: Blob, db: String = "main") throws {
        try _rekey_v2(db: db, keyPointer: key.bytes, keySize: key.bytes.count)
    }

    // MARK: - private
    private func _key_v2(db: String, keyPointer: UnsafePointer<UInt8>, keySize: Int) throws {
        try check(sqlite3_key_v2(handle, db, keyPointer, Int32(keySize)))
        try cipher_key_check()
    }

    private func _rekey_v2(db: String, keyPointer: UnsafePointer<UInt8>, keySize: Int) throws {
        try check(sqlite3_rekey_v2(handle, db, keyPointer, Int32(keySize)))
    }

    // When opening an existing database, sqlite3_key_v2 will not immediately throw an error if
    // the key provided is incorrect. To test that the database can be successfully opened with the
    // provided key, it is necessary to perform some operation on the database (i.e. read from it).
    private func cipher_key_check() throws {
        let _ = try scalar("SELECT count(*) FROM sqlite_master;")
    }
}
#endif
