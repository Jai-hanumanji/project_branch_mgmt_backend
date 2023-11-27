package com.hdfc.AdminCredentials.Service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hdfc.AdminCredentials.Model.Admin;
import com.hdfc.AdminCredentials.Repository.AdminRepository;

@Service
public class AdminService {
	
	@Autowired
	private AdminRepository adminRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	public Admin addAdmin(Admin admin) {
		admin.setPassword(passwordEncoder.encode(admin.getPassword()));
		return adminRepository.save(admin);
	}

	public String deleteAdminById(Long id) {
		
		Admin user = adminRepository.findById(id).orElse(null);
		if(user==null) return "User with id="+id+" not found.";
		adminRepository.delete(user);
		return "User with id="+id+" deleted.";
	}

	public List<Admin> getAllAdmin() {
		return adminRepository.findAll();
	}

}
