package com.hdfc.AdminCredentials.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.hdfc.AdminCredentials.Filter.JWTAuthFilter;
import com.hdfc.AdminCredentials.Service.UserService;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

	@Autowired
	private JWTAuthFilter jwtAuthFilter;
	
	//Authentication
	@Bean
	public UserDetailsService userDetailsService() {
		return new UserService();
	}
	
	
	//Authorization
	//@SuppressWarnings("removal")
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		//System.out.println("in securityconfig");
		return http.csrf(csrf -> csrf.disable()).cors(cors -> cors.disable())
                .authorizeHttpRequests((authorizeHttpRequests) ->authorizeHttpRequests
                .requestMatchers("/admin/getalladmin","/admin/deleteadmin/**","/admin/validatetoken").authenticated()
                .requestMatchers("/admin/welcome", "/admin/authenticate", "/admin/addadmin").permitAll())
                .sessionManagement(management -> management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
	}
	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
    public AuthenticationProvider authenticationProvider(){
		
		//we need to pass who is UserDetails service and what is password encoder, to authenticationProvider.
		//then authenticationProvider will create authentication object.
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		
		authenticationProvider.setUserDetailsService(userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		
		return authenticationProvider;
    }
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
	
//	@Bean
//	public WebSecurityCustomizer webSecurityCustomizer() {
//	    return (web) -> web.ignoring().requestMatchers("/admin/welcome", "/admin/authenticate", "/admin/addadmin");
//	}
	
}
