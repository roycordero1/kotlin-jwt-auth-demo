package com.roycordero.auth.config

import com.roycordero.auth.utils.JwtUtil
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtRequestFilter: OncePerRequestFilter() {

    @Autowired
    private var jwtUtil = JwtUtil()

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {

        val authorizationHeader = request.getHeader("Authorization")

        // Check if correct header
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized!")
            return
        }

        // Validate JWT token
        val jwtToken = authorizationHeader.substring(7)
        val isValidToken = jwtUtil.validateToken(jwtToken)
        if (!isValidToken) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized!")
            return
        }

        // Get claims of token
        val claims = jwtUtil.getClaims(jwtToken)

        val customUserDetails = CustomUserDetails(claims.toString(), claims["id"].toString())
        val authentication = UsernamePasswordAuthenticationToken(
            customUserDetails, null, customUserDetails.authorities
        )
        SecurityContextHolder.getContext().authentication = authentication

        filterChain.doFilter(request, response)
    }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        return request.requestURL.contains("register") || request.requestURL.contains("login")
    }
}