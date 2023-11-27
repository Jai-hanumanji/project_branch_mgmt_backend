package com.hdfc.Feedback.Controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.hdfc.Feedback.Exception.HandleBadRequest;
import com.hdfc.Feedback.FeignClient.CustomerInterface;
import com.hdfc.Feedback.FeignClient.EmployeeInterface;
import com.hdfc.Feedback.FeignClient.JWTTokenValidation;
import com.hdfc.Feedback.FeignClient.ServiceInterface;
import com.hdfc.Feedback.Model.Feedback;
import com.hdfc.Feedback.Service.FeedbackService;
import com.hdfc.Feedback.dto.ResponseDto;

@RestController
@CrossOrigin("http://localhost:3000/")
public class FeedbackController {
	
	@Autowired
	private JWTTokenValidation jwtTokenValidation;
	
	@Autowired
	private FeedbackService feedbackService;
	
	@Autowired
	private ServiceInterface serviceInterface;
	
	@Autowired
	private EmployeeInterface employeeInterface;
	
	@Autowired
	private CustomerInterface customerInterface;

	@PostMapping("/addfeedback")
	public Feedback addFeedback(@RequestBody Feedback feed,@RequestHeader String Authorization) throws HandleBadRequest {
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		return feedbackService.addFeedback(feed);
	}
	
	@GetMapping("/getallfeedback")
	public List<Feedback> getAllFeedback(@RequestHeader String Authorization) throws HandleBadRequest{
		
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		System.out.println("inside feedback controller");
		return feedbackService.getAllFeedback();
	}
	
	@GetMapping("/getfeedbackperbranch/{id}")
	public List<Feedback> getFeedbackPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		return feedbackService.getFeedbackPerBranch(id);
	}
	
	@GetMapping("/getfeedbacksperbranch/{id}")
	public List<ResponseDto> getFeedbacksPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		
		List<Feedback> list = feedbackService.getFeedbackPerBranch(id);
		List<ResponseDto> result = new ArrayList<ResponseDto>();
		
		list.forEach((feed)->{
			String bname = employeeInterface.getBranchNameById(feed.getBranchid(), Authorization);
			String ename = employeeInterface.getEmployeeNameById(feed.getBranchid(), feed.getEmployeeid(), Authorization);
			String cname = customerInterface.getCustomerNameById(feed.getCustomerid(),feed.getBranchid(), Authorization);
			String sname = serviceInterface.serviceNameById(feed.getServiceid(),Authorization);
			Double rating = feed.getRating();
			ResponseDto res = new ResponseDto(cname,sname,ename,bname,rating);
			result.add(res);
		});
		
		return result;
	}
	
	@GetMapping("/avgratingperbranch/{id}")
	public Double avgRatingPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest {
		
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		
		List<Feedback> list = getFeedbackPerBranch(id,Authorization);
		int len = list.size();
		Double totalRating=0.0;
		
		for(Feedback feed:list) {
			totalRating+=feed.getRating();
		}
		
		return Math.round((totalRating/len) * 10.0) / 10.0;
	}
	
	@GetMapping("/mostdemandingserviceperbranch/{id}")
	public List<String> mostDemandingServicePerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		
		List<Feedback> list = getFeedbackPerBranch(id,Authorization);
		Map<Integer ,Double> service = new HashMap<>();
		Map<Integer ,Integer> serviceCount = new HashMap<>();
		
		list.forEach((feed)->{
			
			Double rating = feed.getRating();
			int serviceid = feed.getServiceid();
			
			if(service.containsKey(serviceid)) {
				
				Double totalRating = service.get(serviceid);
				totalRating+=rating;
				service.put(serviceid, totalRating);
				
				int count = serviceCount.get(serviceid);
				serviceCount.put(serviceid, count+1);
			}
			else 
			{
				service.put(serviceid, rating);
				serviceCount.put(serviceid, 1);
			}
		});
		
		Double mostService=Double.MIN_VALUE;
		
		for (Integer key : service.keySet()) {
		    Double value = service.get(key);
		    if(value>mostService) mostService=value;
		}
		
		List<String> mostDemandingServices=new ArrayList<>();
		
		for (Integer key : service.keySet()) {
			
		    Double value = service.get(key);
		    
		    if(value==mostService) {
		    	mostDemandingServices.add(serviceInterface.serviceNameById(key,Authorization));
		    }
		}
		
		return mostDemandingServices;
	}
	
	@GetMapping("/leastdemandingserviceperbranch/{id}")
	public List<String> leastDemandingServicePerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		List<Feedback> list = getFeedbackPerBranch(id,Authorization);
		Map<Integer ,Double> service = new HashMap<>();
		Map<Integer ,Integer> serviceCount = new HashMap<>();
		
		list.forEach((feed)->{
			
			Double rating = feed.getRating();
			int serviceid = feed.getServiceid();
			
			if(service.containsKey(serviceid)) {
				
				Double totalRating = service.get(serviceid);
				totalRating+=rating;
				service.put(serviceid, totalRating);
				
				int count = serviceCount.get(serviceid);
				serviceCount.put(serviceid, count+1);
			}
			else 
			{
				service.put(serviceid, rating);
				serviceCount.put(serviceid, 1);
			}
		});
	
		Double leastService=Double.MAX_VALUE;
		
		for (Integer key : service.keySet()) {
		    Double value = service.get(key);
			if(value<leastService) leastService=value;
		}
		
		List<String> leastDemandingServices=new ArrayList<>();
		
		for (Integer key : service.keySet()) {
			
		    Double value = service.get(key);
		    
			if(value==leastService) {
				leastDemandingServices.add(serviceInterface.serviceNameById(key,Authorization));
			}
		}
		
		return leastDemandingServices;
	}
	
	@GetMapping("/mostdemandingserviceratingperbranch/{id}")
	public Double mostDemandingServiceRatingPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		List<Feedback> list = getFeedbackPerBranch(id,Authorization);
		Map<Integer ,Double> service = new HashMap<>();
		Map<Integer ,Integer> serviceCount = new HashMap<>();
		
		list.forEach((feed)->{
			
			Double rating = feed.getRating();
			int serviceid = feed.getServiceid();
			
			if(service.containsKey(serviceid)) {
				
				Double totalRating = service.get(serviceid);
				totalRating+=rating;
				service.put(serviceid, totalRating);
				
				int count = serviceCount.get(serviceid);
				serviceCount.put(serviceid, count+1);
			}
			else 
			{
				service.put(serviceid, rating);
				serviceCount.put(serviceid, 1);
			}
		});
	
		Double mostService=Double.MIN_VALUE;
		
		for (Integer key : service.keySet()) {
		    Double value = service.get(key);
			if(value>mostService) mostService=value;
		}
			
		Double mostServiceRating=0.0;
		
		for (Integer key : service.keySet()) {
			
		    Double value = service.get(key);
		    
			if(value==mostService) {
				mostServiceRating=value/serviceCount.get(key);
				break;
			}
		}
		mostServiceRating = Math.round(mostServiceRating * 10.0) / 10.0;
		return mostServiceRating;
	}
	
	@GetMapping("/leastdemandingserviceratingperbranch/{id}")
	public Double leastDemandingServiceRatingPerBranch(@PathVariable int id,@RequestHeader String Authorization) throws HandleBadRequest{
		if(!jwtTokenValidation.validateToken(Authorization)) throw new HandleBadRequest("Invalid token");
		List<Feedback> list = getFeedbackPerBranch(id,Authorization);
		Map<Integer ,Double> service = new HashMap<>();
		Map<Integer ,Integer> serviceCount = new HashMap<>();
		
		list.forEach((feed)->{
			
			Double rating = feed.getRating();
			int serviceid = feed.getServiceid();
			
			if(service.containsKey(serviceid)) {
				
				Double totalRating = service.get(serviceid);
				totalRating+=rating;
				service.put(serviceid, totalRating);
				
				int count = serviceCount.get(serviceid);
				serviceCount.put(serviceid, count+1);
			}
			else 
			{
				service.put(serviceid, rating);
				serviceCount.put(serviceid, 1);
			}
		});
	
		Double leastService=Double.MAX_VALUE;
		
		for (Integer key : service.keySet()) {
		    Double value = service.get(key);
			if(value<leastService) leastService=value;
			
		}
		
		Double leastServiceRating=0.0;
		
		for (Integer key : service.keySet()) {
			
		    Double value = service.get(key);
		    
			if(value==leastService) {
				leastServiceRating=value/serviceCount.get(key);
				break;
			}
		}
		leastServiceRating=Math.round(leastServiceRating * 10.0) / 10.0;
		return leastServiceRating;
	}
	

}
