package com.roycordero.auth.services

import com.roycordero.auth.models.User
import com.roycordero.auth.repositories.UserRepository
import org.springframework.stereotype.Service

@Service
class UserService(val userRepository: UserRepository) {

    fun save(user: User): User {
        return userRepository.save(user)
    }

    fun findByEmail(email: String): User? {
        return userRepository.findByEmail(email)
    }

    fun getById(id: Int): User {
        return userRepository.getById(id)
    }
}