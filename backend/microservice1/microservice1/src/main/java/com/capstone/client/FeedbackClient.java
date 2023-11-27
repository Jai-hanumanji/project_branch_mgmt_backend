package com.capstone.client;

import java.util.List;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.capstone.feignclasses.Feedback;

@FeignClient(url="https://mocki.io/v1/a8357a1a-35e6-4fa2-8c9d-a202fb59cfff", name="FEEDBACK-CLIENT")
public interface FeedbackClient {
	
	@GetMapping("") ///getallfeedback
	public List<Feedback> getAllFeedback();
	
	@GetMapping("/getfeedbackperbranch/{id}")
	public List<Feedback> getFeedbackPerBranch(@PathVariable int id);

}
