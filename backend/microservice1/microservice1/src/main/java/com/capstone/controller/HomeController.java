package com.capstone.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.capstone.client.CustomerClient;
import com.capstone.client.FeedbackClient;
import com.capstone.client.JWTTokenValidation;
import com.capstone.client.Exception.HandleBadRequest;
import com.capstone.client.dto.BranchDTO;
import com.capstone.feignclasses.Feedback;
import com.capstone.model.Branch;
import com.capstone.service.BranchService;
import com.capstone.service.EmployeeService;

@RestController
@CrossOrigin("http://localhost:3000/")
public class HomeController {
	
	@Autowired
	private BranchService branchservice;
	@Autowired
	private EmployeeService employeeservice;
	@Autowired
	private CustomerClient customerclient;
	@Autowired
	private FeedbackClient feedbackclient;
	
	@Autowired
	private JWTTokenValidation jwtTokenValidation;
	
	//return no. of employees
	@GetMapping("/employees/{id}")
	public int getBranchEmployeesById(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token.");
		return branchservice.findBranchById(id).getEmployee().size();
	}
	
	@GetMapping("/getemployeenamebyid/{bid}/{eid}")
	public String getEmployeeNameById(@PathVariable Long bid,@PathVariable Long eid,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token.");
		return employeeservice.getEmployeeNameById(bid,eid);
	}
	
	@GetMapping("/getbranchnamebyid/{bid}")
	public String getBranchNameById(@PathVariable Long bid,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token.");
		return employeeservice.getBranchNameById(bid);
	}
	
	@GetMapping("/customers/{id}")
	public int getBranchCustomersById(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token.");
		return customerclient.totalCustomerPerBranch(id);
	}
	
	@GetMapping("/feedback/{id}")
	public List<Feedback> getBranchFeedbackById(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token.");
		return feedbackclient.getAllFeedback();
	}
	
	@PostMapping("/addemployee")
	public Branch addEmployee(@RequestBody Branch emp) {
		return branchservice.addEmployee(emp);
	}
	
	@GetMapping("/getallbranch")
	public List<BranchDTO> getAllBranch(@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token.");
		List<Branch> list = branchservice.getAllBranch();
		List<BranchDTO> result = new ArrayList<BranchDTO>();
		list.forEach((branch)->{
			result.add(new BranchDTO(branch.getId(),branch.getName(),branch.getLocation()));
		});
		return result;
	}
}
