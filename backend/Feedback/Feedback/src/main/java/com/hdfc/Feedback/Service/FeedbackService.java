package com.hdfc.Feedback.Service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.hdfc.Feedback.Model.Feedback;
import com.hdfc.Feedback.Repository.FeedbackRepository;

@Service
public class FeedbackService {
	
	@Autowired
	private FeedbackRepository feedbackRepository;

	public List<Feedback> getAllFeedback() {
		return feedbackRepository.findAll();
	}
	
	public List<Feedback> getFeedbackPerBranch(int id) {
		return feedbackRepository.getFeedbackPerBranch(id);
	}

	public Feedback addFeedback(Feedback feed) {
		return feedbackRepository.save(feed);
	}

}
