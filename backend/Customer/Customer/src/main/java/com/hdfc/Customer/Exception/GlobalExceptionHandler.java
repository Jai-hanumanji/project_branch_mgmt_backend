package com.hdfc.Customer.Exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(HandleBadRequest.class)
	public Map<String,String> handleAccessPermissionException(HandleBadRequest ex) {
    	Map<String,String>  error=new HashMap<String, String>();
		error.put("message",ex.getMessage());
    	return error;
    }
}
