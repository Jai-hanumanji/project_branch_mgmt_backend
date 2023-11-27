package com.hdfc.Customer.FeignClient;

import java.util.List;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;

import com.hdfc.Customer.dto.Feedback;

@FeignClient("FEEDBACK-SERVICE")
public interface CustomerInterface {

	@GetMapping("/getallfeedback")
	List<Feedback> getAllFeedback(@RequestHeader String Authorization);
	
	@GetMapping("/getfeedbackperbranch/{id}")
	List<Feedback> getFeedbackPerBranch(@PathVariable int id,@RequestHeader String Authorization);
}



