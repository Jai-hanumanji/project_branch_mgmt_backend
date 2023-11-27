package com.hdfc.Customer.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Feedback {

	private Long id;
	private Double rating;
	private Long customerid;
	private Long employeeid;
	private Long branchid;
	private Long serviceid;
}
