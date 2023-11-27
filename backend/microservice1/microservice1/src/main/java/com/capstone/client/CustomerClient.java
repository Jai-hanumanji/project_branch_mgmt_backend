package com.capstone.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(url="https://jsonplaceholder.typicode.com/",name="CUSTOMER-CLIENT")
public interface CustomerClient {
	
	@GetMapping("/totalCustomerPerBranch/{id}")
	public int totalCustomerPerBranch(@PathVariable int id);
	
	@GetMapping("/totalcustomer")
	public int totalCustomer();
	
	

}
