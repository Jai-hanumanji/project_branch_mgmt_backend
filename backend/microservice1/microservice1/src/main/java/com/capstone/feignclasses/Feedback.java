package com.capstone.feignclasses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Feedback {

		private int id;
		
		//on scale of 5
		private Double rating;
		private int customerid;
		private int employeeid;
		private int branchid;
		private int serviceid;

}
