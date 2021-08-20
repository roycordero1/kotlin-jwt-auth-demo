package com.roycordero.auth.config

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class CustomUserDetails: UserDetails {

    var data: String? = null

    var userId: String? = null

    constructor(data: String?, userId: String?) {
        this.data = data
        this.userId = userId
    }

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = mutableListOf()

    override fun isEnabled(): Boolean = true

    override fun getUsername(): String = data.orEmpty()

    override fun isCredentialsNonExpired(): Boolean = true

    override fun getPassword(): String = ""

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true
}