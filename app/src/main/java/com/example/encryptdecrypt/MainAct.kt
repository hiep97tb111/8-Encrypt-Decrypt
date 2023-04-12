package com.example.encryptdecrypt

import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class MainAct : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.act_main)

        initViews()
    }

    private fun initViews() {
        findViewById<TextView>(R.id.tvHashMD5).setOnClickListener {
            Log.e("Logger", handleHashMD5("Manchester United"))

            if (compareMD5("Manchester United", handleHashMD5("Manchester United"))) {
                Log.d("Logger", "The input password matches the known hash value")
            } else {
                Log.d("Logger", "The input password does not match the known hash value")
            }
        }

        findViewById<TextView>(R.id.tvAES256ModeCBC).setOnClickListener {
            // Create secretKey or Custom secretKey
            val keyGenerator: KeyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(256)
            val secretKey = keyGenerator.generateKey()
            val secretKeyToString = Base64.encodeToString(secretKey.encoded,Base64.DEFAULT)
            Log.e("Logger SecretKey", secretKeyToString)

            handleEncryptAES256ModeCBC("Micheal Carrick", secretKeyToString
            )
        }

        findViewById<TextView>(R.id.tvRSAModeECB).setOnClickListener {
            handleEncryptAndDecryptRSAModeECB()
        }

    }

    // Encrypt input to HashMD5
    private fun handleHashMD5(inputText: String): String {
        try {
            // Create MD5 Hash
            val digest = MessageDigest.getInstance("MD5")
            digest.update(inputText.toByteArray())
            val messageDigest = digest.digest()

            // Create Hex String
            val hexString = StringBuffer()
            for (element in messageDigest) {
                var h = Integer.toHexString(0xFF and element.toInt())
                while (h.length < 2) h = "0$h"
                hexString.append(h)
            }
            return hexString.toString()

        } catch (e: Exception) {
            e.printStackTrace()
        }
        return ""
    }

    private fun compareMD5(inputText: String, hashMD5: String): Boolean {
        val hashText = handleHashMD5(inputText)
        if (hashText == hashMD5) {
            return true
        }
        return false
    }

    private fun handleEncryptAES256ModeCBC(plainText: String, encryptionKey: String) {
        // Create an instance of the cipher with the AES algorithm and CBC mode
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        // Generate a random initialization vector
        val ivBytes = ByteArray(16)
        val random = SecureRandom()
        random.nextBytes(ivBytes)
        val iv = IvParameterSpec(ivBytes)

        // Generate a key from the encryptionKey
        val keyBytes: ByteArray = encryptionKey.toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val hashedKeyBytes = md.digest(keyBytes)
        val key = SecretKeySpec(hashedKeyBytes, "AES")

        // Initialize the cipher in encryption mode with the key and initialization vector
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)

        // Encrypt the plaintext
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())

        // Combine the initialization vector and encrypted bytes into a single byte array
        val combinedBytes = ByteArray(ivBytes.size + encryptedBytes.size)
        System.arraycopy(ivBytes, 0, combinedBytes, 0, ivBytes.size)
        System.arraycopy(encryptedBytes, 0, combinedBytes, ivBytes.size, encryptedBytes.size)

        // Encode the combined byte array as a Base64 string and return it
        Log.e("Logger Encode", Base64.encodeToString(combinedBytes, Base64.DEFAULT))

        handleDecryptAES256ModeCBC(Base64.encodeToString(combinedBytes, Base64.DEFAULT), encryptionKey
        )
    }

    private fun handleDecryptAES256ModeCBC(encryptedText: String?, encryptionKey: String) {
        // Decode the Base64-encoded string into a byte array
        val combinedBytes = Base64.decode(encryptedText, Base64.DEFAULT)

        // Split the byte array into the initialization vector and encrypted bytes
        val ivBytes = ByteArray(16)
        System.arraycopy(combinedBytes, 0, ivBytes, 0, ivBytes.size)
        val encryptedBytes = ByteArray(combinedBytes.size - ivBytes.size)
        System.arraycopy(combinedBytes, ivBytes.size, encryptedBytes, 0, encryptedBytes.size)

        // Generate a key from the encryptionKey
        val keyBytes: ByteArray = encryptionKey.toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val hashedKeyBytes = md.digest(keyBytes)
        val key = SecretKeySpec(hashedKeyBytes, "AES")

        // Create an instance of the cipher with the AES algorithm and CBC mode
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        // Initialize the cipher in decryption mode with the key and initialization vector
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(ivBytes))

        // Decrypt the encrypted bytes
        val decryptedBytes = cipher.doFinal(encryptedBytes)

        // Convert the decrypted bytes back to a string and return it
        Log.e("Logger Decode", String(decryptedBytes))

    }

    private fun handleEncryptAndDecryptRSAModeECB() {
        val plainText = "Manchester United"
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

        // Encrypt use publicKey
        val publicKey = keyPair.public
        val publicKeyBytes = publicKey.encoded
        val publicKeyString = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT)
        Log.e("Logger PublicKey ", publicKeyString.toString())

        val messageBytes = plainText.toByteArray()
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(messageBytes)

        val encryptedString = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
        Log.e("Logger EnCryptString", encryptedString)

        // Decrypt use privateKey
        val privateKey = keyPair.private
        val privateKeyBytes = privateKey.encoded
        val privateKeyString = Base64.encodeToString(privateKeyBytes, Base64.DEFAULT)
        Log.e("Logger PrivateKey ", privateKeyString.toString())

        val encryptedBytes1 = Base64.decode(encryptedString, Base64.DEFAULT)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptedBytes = cipher.doFinal(encryptedBytes1)

        val decryptedString = String(decryptedBytes, StandardCharsets.UTF_8)
        Log.e("Logger DecryptString", decryptedString)
    }
}