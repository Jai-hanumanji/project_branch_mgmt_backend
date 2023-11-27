package com.hdfc.Feedback.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class ResponseDto {

	private String customername;
	private String servicename;
	private String employeename;
	private String branchname;
	private Double rating;
	public ResponseDto(String customername, String servicename, String employeename, String branchname, Double rating) {
		this.customername = customername;
		this.servicename = servicename;
		this.employeename = employeename;
		this.branchname = branchname;
		this.rating = rating;
	}
	
}
