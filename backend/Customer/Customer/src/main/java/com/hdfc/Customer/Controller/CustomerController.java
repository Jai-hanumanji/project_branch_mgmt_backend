package com.hdfc.Customer.Controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.hdfc.Customer.Exception.HandleBadRequest;
import com.hdfc.Customer.FeignClient.CustomerInterface;
import com.hdfc.Customer.FeignClient.JWTTokenValidation;
import com.hdfc.Customer.Service.CustomerService;
import com.hdfc.Customer.dto.Feedback;
import com.hdfc.Customer.model.Customer;

@RestController
@CrossOrigin("http://localhost:3000/")
public class CustomerController {
	
	@Autowired
	private JWTTokenValidation jwtTokenValidation;
	
	@Autowired
	private CustomerService customerService;
	
	@Autowired
	private CustomerInterface customerInterface;
	
	@GetMapping("/getcustomername/{bid}/{cid}")
	public String getCustomerNameById(@PathVariable Long cid,@PathVariable Long bid,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return customerService.getCustomerNameById(bid,cid);
	}
	
	@GetMapping("/getallfeedback")
	public List<Feedback> getFeedback(@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return customerInterface.getAllFeedback(Authorization);
	}
	
	@GetMapping("getallcustomer")
	public List<Customer> getAllCustomer(@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return customerService.getAllCustomer();
	}
	
	@PostMapping("addcustomer")
	public Customer addCustomer(@RequestBody Customer customer,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return customerService.addCustomer(customer);
	}
	
	@GetMapping("/totalcustomer")
	public int totalCustomer(@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return customerService.getTotalCustomer();
	}
	
	@GetMapping("/totalcustomer/{id}")
	public int totalCustomerPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return customerService.getTotalCustomerPerBranch(id);
	}
	

}
