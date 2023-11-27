package com.hdfc.Feedback.FeignClient;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient("ADMINCREDENTIALS-SERVICE")
public interface JWTTokenValidation {

	@GetMapping("/admin/validatetoken")
	public Boolean validateToken(@RequestHeader String Authorization);
}
