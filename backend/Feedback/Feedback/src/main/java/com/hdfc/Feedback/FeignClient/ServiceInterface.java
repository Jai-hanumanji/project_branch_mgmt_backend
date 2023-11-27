package com.hdfc.Feedback.FeignClient;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;


@FeignClient("SERVICES-SERVICE")
public interface ServiceInterface {
	
	@GetMapping("servicename/{id}")
	public String serviceNameById(@PathVariable int id,@RequestHeader String Authorization);
	
}
