package com.roycordero.auth.utils

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Component
class JwtUtil {

    val publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCAuii+IiBoGHeQPzYi1MCPKgVmDG/ymEovWQsw4DxY1rezfzZny+5M1q+LhLiKcHlvZgzgdGG5fAEusgDvxBDvIeKoTBAyHyegwnA9jU+xNVgtJa3qNSQ9IWIBqmxPPGxsEQxrelCAb8BCWEX4VKNPTbONcycOd2z4wypZTdPx+QIDAQAB"

    fun validateToken(token: String): Boolean {
        return try {

            val decoder = Base64.getDecoder()
            val publicKeyBytesArray = decoder.decode(publicKeyStr)
            val publicKeySpec = X509EncodedKeySpec(publicKeyBytesArray)
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(publicKeySpec)

            Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun getClaims(token: String): Claims {

        val decoder = Base64.getDecoder()
        val publicKeyBytesArray = decoder.decode(publicKeyStr)
        val publicKeySpec = X509EncodedKeySpec(publicKeyBytesArray)
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKey = keyFactory.generatePublic(publicKeySpec)

        return Jwts
            .parser()
            .setSigningKey(publicKey)
            .parseClaimsJws(token)
            .body
    }
}