package com.hdfc.Services.Controller;

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

import com.hdfc.Services.Exception.HandleBadRequest;
import com.hdfc.Services.FeignClient.CustomerFeign;
import com.hdfc.Services.FeignClient.EmployeeInterface;
import com.hdfc.Services.FeignClient.JWTTokenValidation;
import com.hdfc.Services.Model.Service;
import com.hdfc.Services.Repository.ServiceRepository;
import com.hdfc.Services.dto.OverallResponse;
import com.hdfc.Services.dto.ResponsePerBranch;
import com.hdfc.Services.dto.ServiceRequestResponse;

@RestController
@CrossOrigin("http://localhost:3000/")
public class ServiceController {
	
	@Autowired
	private CustomerFeign customerFeign;
	
	@Autowired
	private JWTTokenValidation jwtTokenValidation;
	
	@Autowired
	private ServiceRepository serviceRepository;
	
	@Autowired
	private EmployeeInterface employeeInterface;

	@PostMapping("makeservicerequest")
	public Service makeServiceRequest(@RequestBody Service serviceRequest,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return serviceRepository.save(serviceRequest);
	}
	
	@GetMapping("getallservicerequest")
	public List<OverallResponse> getAllServicerequest(@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		
		List<ServiceRequestResponse> list = serviceRepository.getAllServicerequest();
		List<OverallResponse> result = new ArrayList<OverallResponse>();
		list.forEach((item)->{
			System.out.println(item);
			result.add(new OverallResponse(customerFeign.getCustomerNameById(item.getCustomerid(), item.getBranchid(), Authorization),item.getEmployeeid(),item.getServicename(), item.getBranchid() ,item.getStatus(),item.getStarttime(),item.getEndtime()));
		});
		
		return result;
	}
	
	@GetMapping("servicename/{id}")
	public String serviceNameById(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		Service serv = serviceRepository.findById(id).orElse(null);
		
		if(serv==null) return "invalid service id";
		
		return serv.getName();
	}
	
	@GetMapping("getallservicerequestperbranch/{id}")
	public List<ResponsePerBranch> getAllServicerequestPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		
		List<ServiceRequestResponse>  list = serviceRepository.getAllServicerequestPerBranch(id);
		List<ResponsePerBranch> result =new ArrayList<ResponsePerBranch>();
		list.forEach((item)->{
			result.add(new ResponsePerBranch(customerFeign.getCustomerNameById(item.getCustomerid(), item.getBranchid(), Authorization),item.getServicename() ,employeeInterface.getEmployeeNameById(item.getBranchid(), item.getEmployeeid(), Authorization),item.getStatus(),item.getStarttime(),item.getEndtime()));
		});
		
		return result;
	}
	
	@GetMapping("getallcompletedservicerequestperbranch/{id}")
	public List<ResponsePerBranch> getAllCompletedServicerequestPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		
		List<ServiceRequestResponse> list = serviceRepository.getAllCompletedServicerequestPerBranch("completed",id);
		List<ResponsePerBranch> result = new ArrayList<ResponsePerBranch>();
		
		list.forEach((item)->{
			result.add(new ResponsePerBranch(customerFeign.getCustomerNameById(item.getCustomerid(), item.getBranchid(), Authorization),item.getServicename() ,employeeInterface.getEmployeeNameById(item.getBranchid(), item.getEmployeeid(), Authorization),item.getStatus(),item.getStarttime(),item.getEndtime()));
		});
		
		return result;
	}
	
	@GetMapping("getallpendingservicerequestperbranch/{id}")
	public List<ResponsePerBranch> getAllPendingServicerequestPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		
		List<ServiceRequestResponse> list = serviceRepository.getAllPendingServicerequestPerBranch("pending",id);
		List<ResponsePerBranch> result = new ArrayList<ResponsePerBranch>();
		
		list.forEach((item)->{
			result.add(new ResponsePerBranch(customerFeign.getCustomerNameById(item.getCustomerid(), item.getBranchid(), Authorization),item.getServicename() ,employeeInterface.getEmployeeNameById(item.getBranchid(), item.getEmployeeid(), Authorization),item.getStatus(),item.getStarttime(),item.getEndtime()));
		});
		
		return result;
	}
	
	@GetMapping("servicesoldperbranch/{id}")
	public int totalServiceSoldPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return getAllServicerequestPerBranch(id,Authorization).size();
	}
	
	@GetMapping("servicesoldoverall")
	public int totalServiceSoldOverall(@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("invalid token");
		return getAllServicerequest(Authorization).size();
	}
	
	

}
