//package com.hdfc.Customer.Interceptor;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//import org.springframework.web.servlet.HandlerInterceptor;
//
//import com.hdfc.Customer.FeignClient.JWTTokenValidation;
//import com.hdfc.Customer.dto.jwttoken;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//@Component
//public class RequestInterceptor implements HandlerInterceptor {
//	
//	@Autowired
//	private JWTTokenValidation jwtTokenValidation;
//
//	@Override
//	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
//			throws Exception {
//		
//		System.out.println("in customer");
//		System.out.println("1 - pre handle.");
//        System.out.println("METHOD type:" + request.getMethod());
//        System.out.println("Request URI: " + request.getRequestURI());
//		System.out.println("Header:" + request.getHeader("Authorization"));
//		jwttoken.token=request.getHeader("Authorization");
//		
//		return jwtTokenValidation.validateToken(jwttoken.token);
//	}
//
//}
