package com.roycordero.auth.controllers

import com.roycordero.auth.config.CustomUserDetails
import com.roycordero.auth.dtos.LoginDTO
import com.roycordero.auth.dtos.LoginResponseDTO
import com.roycordero.auth.dtos.Message
import com.roycordero.auth.dtos.RegisterDTO
import com.roycordero.auth.models.User
import com.roycordero.auth.services.UserService
import com.roycordero.auth.utils.JwtUtil
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.*
import java.lang.Exception
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@RestController
@RequestMapping("api")
class AuthController(val userService: UserService) {

    @PostMapping("register")
    fun register(@RequestBody body: RegisterDTO): ResponseEntity<User> {
        val user = User()
        user.name = body.name
        user.email = body.email
        user.password = body.password

        return ResponseEntity.ok(userService.save(user))
    }

    @PostMapping("login")
    fun login(@RequestBody body: LoginDTO, response: HttpServletResponse): ResponseEntity<LoginResponseDTO> {

        val user = userService.findByEmail(body.email)
            ?: return ResponseEntity.badRequest().body(
                LoginResponseDTO(
                    message = "User not found!",
                    token = ""
                )
            )

        if (!user.comparePassword(body.password)) {
            return ResponseEntity.badRequest().body(
                LoginResponseDTO(
                    message = "Invalid password!",
                    token = ""
                )
            )
        }

        val issuer = user.id.toString()

        val claims: Map<String, Any> = mapOf("data" to "This is the data", "email" to user.email, "id" to user.id)

        val privateKeyStr = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIC6KL4iIGgYd5A/NiLUwI8qBWYMb/KYSi9ZCzDgPFjWt7N/NmfL7kzWr4uEuIpweW9mDOB0Ybl8AS6yAO/EEO8h4qhMEDIfJ6DCcD2NT7E1WC0lreo1JD0hYgGqbE88bGwRDGt6UIBvwEJYRfhUo09Ns41zJw53bPjDKllN0/H5AgMBAAECgYBQjS1FnTFOMlFPMF79+MfuTktGim3bDrUNX9kC4q6goOwfJHG1DgW2i3kaAxk/eBZlQSS5p9onKZPL1pODddtqAxJA6wXy/VnpvEnlm3rof+Kzv+pq4UUS6ki2J+2DVPvsuH3oRljvSddfROwu3PDoHP0vatMNi40ULJPypWoJqQJBANCmmhRL5tHWmgmDvKSQQbFFtMSIvUKUfb+SblGOdc9ESmBXytFZziHwWwVQBJlQcfBPuZUTVNysSLC8q03HZEcCQQCd8HXbvHdT4LtGlAZTQIc0/6hxIxxR26QrV5gjJZD/y38ccfRE1A22Z8LkRjfKqAqpAIVzXettaqgyPSTPJFe/AkB/o1sgTWpPNYOXjHIrDWBSbHzvuWJlx2bBeXdpBsgE2hbRpwMYXGKgGmPj9RZLH44D3xF9I41HTVFOZKw6cV5jAkA4+5G6NtQiqhlHTI6/qK9fesHuF8nW6tTfYlocjCg1cdkpjR+hWZSc8/DH5WGpt1kpQmvjhMY1Et8eSRsntSgHAkBml5Xnje+8zTXxwoC/D2+fZf8yiMTTBOKvL4nqf/iKaZDE3H5qyp/lrAWa1+6dIekx8m9YZcr9aj3PIu0pjAne"

        val decoder = Base64.getDecoder()
        val privateKeyBytesArray = decoder.decode(privateKeyStr)
        val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytesArray)
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(privateKeySpec)

        val jwt = Jwts.builder()
            .setIssuer(issuer)
            .setSubject("User")
            .setClaims(claims)
            .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7))
            .signWith(SignatureAlgorithm.RS256, privateKey).compact()

        val response = LoginResponseDTO(
            message = "Success!",
            token = jwt
        )

        return ResponseEntity.ok(response)
    }

    @GetMapping("user")
    fun user(request: HttpServletRequest): ResponseEntity<Any> {

        try {

            val userId = (SecurityContextHolder.getContext().authentication.principal as CustomUserDetails).userId
                ?: return ResponseEntity.status(401).body(Message("Unauthenticated!"))

            return ResponseEntity.ok(userService.getById(userId.toInt()))

        } catch (e: Exception) {
            return ResponseEntity.status(401).body(Message("Unauthenticated!"))
        }
    }
}