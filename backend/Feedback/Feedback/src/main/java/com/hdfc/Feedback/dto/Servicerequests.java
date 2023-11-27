package com.hdfc.Feedback.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Servicerequests {
	
	private String customername;
	private String servicename;
	private String employeename;
	private String status;
	private String starttime;
	private String endtime;

}
