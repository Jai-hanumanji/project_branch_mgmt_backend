package com.capstone.client;

import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(url="https://jsonplaceholder.typicode.com/", name="SERVICEREQUEST-CLIENT")
public interface ServiceRequestClient {
	

}
