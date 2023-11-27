package com.hdfc.Feedback.FeignClient;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient("CUSTOMER-SERVICE")
public interface CustomerInterface {
	
	@GetMapping("/getcustomername/{bid}/{cid}")
	public String getCustomerNameById(@PathVariable Long cid,@PathVariable Long bid,@RequestHeader String Authorization);

}
