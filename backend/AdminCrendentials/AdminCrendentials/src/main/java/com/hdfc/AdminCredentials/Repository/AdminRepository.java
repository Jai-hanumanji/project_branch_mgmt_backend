package com.hdfc.AdminCredentials.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.hdfc.AdminCredentials.Model.Admin;

@Repository
public interface AdminRepository extends JpaRepository<Admin, Long> {

	Admin findByName(String username);
	
}
