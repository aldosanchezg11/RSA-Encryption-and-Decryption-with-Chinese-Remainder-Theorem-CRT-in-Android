package com.example.rsacrt

import android.os.Build
import android.os.Bundle
import android.widget.EditText
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.annotation.RequiresApi
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.Cipher
import java.math.BigInteger
import java.security.interfaces.RSAPrivateCrtKey


class MainActivity : ComponentActivity() {
    private lateinit var messageInput: EditText
    private lateinit var encryptedMessage: TextView
    private lateinit var decryptedMessage: TextView
    private lateinit var encryptionTime: TextView
    private lateinit var decryptionTime: TextView

    private lateinit var publicKey: RSAPublicKey
    private lateinit var privateKey: RSAPrivateKey
    private lateinit var privateKeycrt: RSAPrivateCrtKey

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        messageInput = findViewById(R.id.messageInput)
        encryptedMessage = findViewById(R.id.encryptedMessage)
        decryptedMessage = findViewById(R.id.decryptedMessage)
        encryptionTime = findViewById(R.id.encryptionTime)
        decryptionTime = findViewById(R.id.decryptionTime)

        generateKeyPair()

        findViewById<TextView>(R.id.encryptButton).setOnClickListener {
            val start = System.currentTimeMillis()
            val encryptedText = encrypt(messageInput.text.toString())
            val end = System.currentTimeMillis()
            encryptedMessage.text = encryptedText
            encryptionTime.text = "Encryption Time: ${end - start} ms"
        }

        findViewById<TextView>(R.id.decryptCrtButton).setOnClickListener {
            val start = System.currentTimeMillis()
            val decryptedText = decryptUsingCRT(encryptedMessage.text.toString())
            val end = System.currentTimeMillis()
            decryptedMessage.text = decryptedText
            decryptionTime.text = "Decryption Time with CRT: ${end - start} ms"
        }

        findViewById<TextView>(R.id.decryptButton).setOnClickListener {
            val start = System.currentTimeMillis()
            val decryptedText = decrypt(encryptedMessage.text.toString())
            val end = System.currentTimeMillis()
            decryptedMessage.text = decryptedText
            decryptionTime.text = "Decryption Time: ${end - start} ms"
        }
    }

    private fun generateKeyPair() {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()
        publicKey = keyPair.public as RSAPublicKey
        privateKey = keyPair.private as RSAPrivateKey
        privateKeycrt = keyPair.private as RSAPrivateCrtKey
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun encrypt(message: String): String {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(message.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }
    @RequiresApi(Build.VERSION_CODES.O)
    private fun decrypt(encryptedMessage: String): String {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage))
        return String(decryptedBytes)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun decryptUsingCRT(encryptedMessage: String): String {
        val encryptedBytes = Base64.getDecoder().decode(encryptedMessage)

        // Convert encrypted bytes to BigInteger
        val c = BigInteger(1, encryptedBytes)

        // Compute the CRT parameters
        val p = privateKeycrt.primeP
        val q = privateKeycrt.primeQ
        val dp = privateKeycrt.primeExponentP
        val dq = privateKeycrt.primeExponentQ
        val qInv = privateKeycrt.crtCoefficient

        // Perform the CRT operations
        val m1 = c.modPow(dp, p)
        val m2 = c.modPow(dq, q)
        val h = qInv.multiply(m1.subtract(m2)).mod(p)
        val m = m2.add(h.multiply(q))

        // Convert the decrypted BigInteger back to bytes
        val decryptedBytes = m.toByteArray()
        return String(decryptedBytes)
    }
}

