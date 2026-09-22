package com.blackbox.plog.utils

import android.annotation.SuppressLint
import android.util.Log
import androidx.annotation.Keep
import com.blackbox.plog.pLogs.impl.PLogImpl
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@SuppressLint("GetInstance")
@Keep
class Encrypter {

    companion object {
        private const val ALGORITHM = "AES/GCM/NoPadding"

        private const val AES_KEY_SIZE_BYTES = 32
        private const val GCM_IV_SIZE_BYTES = 12
        private const val GCM_TAG_SIZE_BITS = 128

        /*
         * Every encrypted record is stored as:
         *
         * [4-byte MAGIC]
         * [12-byte IV]
         * [4-byte ciphertext length]
         * [ciphertext + GCM authentication tag]
         */
        private const val FILE_MAGIC = 0x504C4F47 // "PLOG"

        private val secureRandom = SecureRandom()
    }

    /*
     * This validates that a key is provided.
     */
    fun checkIfKeyValid(encKey: String): String {

        if (encKey.isEmpty()) {
            Log.e("checkIfKeyValid", "No Key provided!")
            return ""
        }

        return encKey
    }

    /*
     * Generates a 256-bit AES key from the supplied secret.
     *
     * SHA-256 always produces exactly 32 bytes, which gives us
     * a valid AES-256 key regardless of the input String length.
     */
    fun generateKey(encKey: String): SecretKey {

        val validKey = checkIfKeyValid(encKey)

        require(validKey.isNotEmpty()) {
            "Encryption key cannot be empty"
        }

        val keyBytes = MessageDigest
            .getInstance("SHA-256")
            .digest(validKey.toByteArray(Charsets.UTF_8))

        return SecretKeySpec(keyBytes, "AES")
    }

    /*
     * Generates a fresh 96-bit IV for every encryption operation.
     *
     * GCM requires IV uniqueness when the same key is reused.
     */
    private fun generateIV(): ByteArray {
        return ByteArray(GCM_IV_SIZE_BYTES).also {
            secureRandom.nextBytes(it)
        }
    }

    /*
     * Creates a new GCM Cipher.
     */
    private fun createCipher(): Cipher {
        return Cipher.getInstance(ALGORITHM)
    }

    /*
     * Encrypts a single String and returns:
     *
     * IV + ciphertext + authentication tag
     */
    private fun encryptData(
        data: String,
        key: SecretKey
    ): Pair<ByteArray, ByteArray> {

        val iv = generateIV()

        val cipher = createCipher()

        val spec = GCMParameterSpec(
            GCM_TAG_SIZE_BITS,
            iv
        )

        cipher.init(
            Cipher.ENCRYPT_MODE,
            key,
            spec
        )

        val encryptedData = cipher.doFinal(
            data.toByteArray(Charsets.UTF_8)
        )

        return Pair(iv, encryptedData)
    }

    /*
     * Decrypts one encrypted record.
     */
    private fun decryptData(
        iv: ByteArray,
        encryptedData: ByteArray,
        key: SecretKey
    ): String {

        val cipher = createCipher()

        val spec = GCMParameterSpec(
            GCM_TAG_SIZE_BITS,
            iv
        )

        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            spec
        )

        val decryptedData = cipher.doFinal(encryptedData)

        return decryptedData.toString(Charsets.UTF_8)
    }

    /*
     * Appends encrypted data to an existing file.
     *
     * Each append operation becomes a separate authenticated
     * GCM record with its own unique IV.
     */
    @Synchronized
    fun appendToFileEncrypted(
        dataToWrite: String,
        key: SecretKey,
        filePath: String
    ) {

        try {

            val encrypted = encryptData(
                dataToWrite,
                key
            )

            val iv = encrypted.first
            val ciphertext = encrypted.second

            DataOutputStream(
                FileOutputStream(
                    File(filePath),
                    true
                )
            ).use { output ->

                output.writeInt(FILE_MAGIC)

                output.write(iv)

                output.writeInt(ciphertext.size)

                output.write(ciphertext)

                output.flush()
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /*
     * Replaces the file with one encrypted GCM record.
     */
    @Synchronized
    fun writeToFileEncrypted(
        dataToWrite: String,
        key: SecretKey,
        filePath: String
    ) {

        try {

            val encrypted = encryptData(
                dataToWrite,
                key
            )

            val iv = encrypted.first
            val ciphertext = encrypted.second

            DataOutputStream(
                FileOutputStream(
                    filePath,
                    false
                )
            ).use { output ->

                output.writeInt(FILE_MAGIC)

                output.write(iv)

                output.writeInt(ciphertext.size)

                output.write(ciphertext)

                output.flush()
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /*
     * Reads all encrypted records from the file and decrypts them.
     */
    @Synchronized
    fun readFileDecrypted(filePath: String): String {

        val secretKey = PLogImpl.getConfig()?.secretKey
            ?: return ""

        val result = StringBuilder()

        try {

            DataInputStream(
                FileInputStream(filePath)
            ).use { input ->

                while (true) {

                    try {

                        val magic = input.readInt()

                        if (magic != FILE_MAGIC) {
                            throw IOException(
                                "Invalid encrypted PLog file format"
                            )
                        }

                        val iv = ByteArray(GCM_IV_SIZE_BYTES)

                        input.readFully(iv)

                        val encryptedSize = input.readInt()

                        if (encryptedSize < 0) {
                            throw IOException(
                                "Invalid encrypted data size"
                            )
                        }

                        val encryptedData =
                            ByteArray(encryptedSize)

                        input.readFully(encryptedData)

                        val decrypted = decryptData(
                            iv,
                            encryptedData,
                            secretKey
                        )

                        result.append(decrypted)

                    } catch (e: EOFException) {
                        break
                    }
                }
            }

        } catch (e: AEADBadTagException) {

            Log.e(
                "Encrypter",
                "Encrypted log authentication failed",
                e
            )

        } catch (e: Exception) {

            e.printStackTrace()
        }

        return cleanUpFile(result.toString())
    }

    private fun cleanUpFile(text: String): String {

        return try {

            val t1 = cleanTextContent(text)
                .replace(
                    Regex("[^\\x00-\\x7f]+"),
                    ""
                )

            val t2 = t1.replace(
                "[\\r\\n]+".toRegex(),
                "\n"
            )

            val t3 = t2.trimStart()

            t3.replace(
                Regex("[\\r\\t ]+"),
                " "
            )

        } catch (e: Exception) {

            e.printStackTrace()

            text
        }
    }

    private fun cleanTextContent(text: String): String {

        var cleanedText = text

        /*
         * Erases ASCII control characters.
         */
        cleanedText = cleanedText.replace(
            "[\\p{Cntrl}]".toRegex(),
            "\n"
        )

        return cleanedText.trim { it <= ' ' }
    }

    /*
     * Converts String to UTF-8 byte array.
     */
    @Synchronized
    fun String.toBytes(): ByteArray {
        return this.toByteArray(Charsets.UTF_8)
    }
}