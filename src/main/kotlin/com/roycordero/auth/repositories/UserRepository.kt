package com.roycordero.auth.repositories

import com.roycordero.auth.models.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository: JpaRepository<User, Int> {

    fun findByEmail(email: String): User?
}