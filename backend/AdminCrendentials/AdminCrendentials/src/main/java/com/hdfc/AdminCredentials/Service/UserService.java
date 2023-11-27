package com.hdfc.AdminCredentials.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hdfc.AdminCredentials.Model.Admin;
import com.hdfc.AdminCredentials.Repository.AdminRepository;
import com.hdfc.AdminCredentials.Security.UserToUserDetails;

@Service
public class UserService implements UserDetailsService {
	
	@Autowired
	private AdminRepository adminRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Admin user =  adminRepository.findByName(username);
		
		if(user==null) throw new UsernameNotFoundException("User not found");
		
		UserToUserDetails userDetails = new UserToUserDetails(user);
		
		return userDetails;
	}

}
