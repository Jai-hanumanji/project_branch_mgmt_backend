package com.hdfc.Services.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ServiceRequestResponse {

	private Long customerid;
	private Long branchid;
	private String servicename;
	private Long  employeeid;
	private String status;
	private String starttime;
	private String endtime;
	
	

}
