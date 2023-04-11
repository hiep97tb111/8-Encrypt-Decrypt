package com.example.encryptdecrypt

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest

class MainAct : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.act_main)

        initViews()
    }

    private fun initViews() {
        findViewById<TextView>(R.id.tvHashMD5).setOnClickListener {
            Log.e("Logger", handleHashMD5("Manchester United"))

            if(compareMD5("Manchester United", handleHashMD5("Manchester United"))){
                Log.d("Logger", "The input password matches the known hash value")
            }else{
                Log.d("Logger", "The input password does not match the known hash value")
            }
        }

    }

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

    private fun compareMD5(inputText: String, hashMD5: String): Boolean{
        val hashText = handleHashMD5(inputText)
        if (hashText == hashMD5) {
            return true
        }
        return false
    }
}