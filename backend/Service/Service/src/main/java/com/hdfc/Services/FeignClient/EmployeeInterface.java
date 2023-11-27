package com.hdfc.Services.FeignClient;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient("EMPLOYEE-SERVICE")
public interface EmployeeInterface {
	@GetMapping("/getemployeenamebyid/{bid}/{eid}")
	public String getEmployeeNameById(@PathVariable Long bid,@PathVariable Long eid,@RequestHeader String Authorization) ;
	

}
